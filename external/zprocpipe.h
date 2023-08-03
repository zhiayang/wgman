// zprocpipe.h
// Copyright (c) 2022, zhiayang
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdio>
#include <cstdlib>
#include <cstddef>
#include <cstdint>

#include <cstring>
#include <string>
#include <vector>
#include <utility>
#include <optional>
#include <filesystem>
#include <string_view>

#if defined(__unix__) || defined(__linux__) || defined(__APPLE__)
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/wait.h>
#include <sys/poll.h>
#include <sys/signal.h>

#elif defined(_WIN32)
#define WIN32_LEAN_AND_MEAN 1
#define NOMINMAX 1
#include <windows.h>
#include <io.h>

static constexpr int STDIN_FILENO = 0;
static constexpr int STDOUT_FILENO = 1;
static constexpr int STDERR_FILENO = 2;

using ssize_t = long long;
#else
#error "unsupported platform"
#endif



namespace zprocpipe
{
	namespace os
	{
#if defined(_WIN32)
		using Fd = HANDLE;
		using Pid = HANDLE;
		static constexpr Fd FD_NONE = nullptr;

#error "windows is not supported atm"

		inline LPSTR GetErrorCodeAsString(DWORD error)
		{
			// https://stackoverflow.com/questions/1387064/how-to-get-the-error-
			// message-from-the-error-code-returned-by-getlasterror
			LPSTR messageBuffer = nullptr;

			DWORD size = FormatMessage(
			    FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr,
			    error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), reinterpret_cast<LPSTR>(&messageBuffer), 0, nullptr);

			return messageBuffer;
		}

		inline LPSTR GetLastErrorAsString()
		{
			DWORD error = GetLastError();
			return GetErrorCodeAsString(error);
		}
#else

		using Fd = int;
		using Pid = pid_t;
		static constexpr Fd FD_NONE = -1;

		inline void close_file(Fd fd);
		inline void dupe_fd2(Fd src, Fd dst)
		{
			// dup2 closes dst for us.
			if(dup2(src, dst) < 0)
			{
				fprintf(stderr, "dup2(%d, %d): %s\n", src, dst, strerror(errno));
				exit(1);
			}

			os::close_file(src);
		}
#endif

		inline const char* strerror_wrapper()
		{
#if defined(_WIN32)
			static char buf[512] {};
			strerror_s(buf, 512, errno);
			return buf;
#else
			return strerror(errno);
#endif
		}

		struct PipeDes
		{
			Fd read_end;
			Fd write_end;
		};

		struct FileOpenFlags
		{
			bool _need_write = false;
			bool _should_create = false;
			bool _append_mode = false;
			bool _truncate_mode = false;
			int _create_perms = 0664;

			inline FileOpenFlags& needs_write(bool x)
			{
				_need_write = x;
				return *this;
			}
			inline FileOpenFlags& should_create(bool x)
			{
				_should_create = x;
				return *this;
			}
			inline FileOpenFlags& append_mode(bool x)
			{
				_append_mode = x;
				return *this;
			}
			inline FileOpenFlags& truncate_mode(bool x)
			{
				_truncate_mode = x;
				return *this;
			}
			inline FileOpenFlags& create_perms(int x)
			{
				_create_perms = x;
				return *this;
			}
		};

		inline os::Fd open_file(const char* path, FileOpenFlags fof)
		{
			int flags = 0;
			Fd fd = 0;

#if defined(_WIN32)

			SECURITY_ATTRIBUTES attr {};
			memset(&attr, 0, sizeof(attr));
			attr.nLength = sizeof(attr);
			attr.bInheritHandle = true;

			fd = CreateFile(path, GENERIC_READ | (fof._need_write ? GENERIC_WRITE : 0), FILE_SHARE_READ, &attr,
			    fof._should_create ? OPEN_ALWAYS : OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

			if(fd == INVALID_HANDLE_VALUE)
			{
				fprintf(stderr, "CreateFile(): %s", GetLastErrorAsString());
				exit(1);
			}

#else
			if(fof._need_write)
				flags |= O_RDWR;
			else
				flags |= O_RDONLY;

			if(fof._should_create)
				flags |= O_CREAT;
			if(fof._truncate_mode)
				flags |= O_TRUNC;
			else if(fof._append_mode)
				flags |= O_APPEND;

			if(fof._should_create)
				fd = open(path, flags, fof._create_perms);
			else
				fd = open(path, flags);

			if(fd < 0)
			{
				fprintf(stderr, "open('%s'): %s", path, os::strerror_wrapper());
				exit(1);
			}
#endif

			return fd;
		}
		inline void close_file(Fd fd)
		{
#if defined(_WIN32)
			if(!CloseHandle(fd))
			{
				fprintf(stderr, "CloseHandle(): %s\n", GetLastErrorAsString());
				exit(1);
			}
#else
			if(close(fd) < 0)
			{
				fprintf(stderr, "close(%d): %s\n", fd, strerror(errno));
				exit(1);
			}
#endif
		}

		inline PipeDes make_pipe()
		{
#if defined(_WIN32)
			Fd p_read;
			Fd p_write;
			SECURITY_ATTRIBUTES attr {};
			memset(&attr, 0, sizeof(attr));
			attr.nLength = sizeof(attr);
			attr.bInheritHandle = true;

			if(!CreatePipe(&p_read, &p_write, &attr, 0))
			{
				fprintf(stderr, "CreatePipe(): %s\n", GetLastErrorAsString());
				exit(1);
			}

			return PipeDes { p_read, p_write };
#else
			if(int p[2]; pipe(p) < 0)
			{
				fprintf(stderr, "pipe(): %s\n", strerror(errno));
				exit(1);
			}
			else
			{
				// set the pipes to close on exec, so that we do not have dangling write ends
				// left open in children.
				if(fcntl(p[0], F_SETFD, FD_CLOEXEC) < 0 || fcntl(p[1], F_SETFD, FD_CLOEXEC) < 0)
				{
					fprintf(stderr, "fcntl(FD_CLOEXEC): %s\n", strerror(errno));
					exit(1);
				}

				return PipeDes { .read_end = p[0], .write_end = p[1] };
			}
#endif
		}

		inline os::Fd dupe_fd(os::Fd src)
		{
			if(src == os::FD_NONE)
				return src;

#if defined(_WIN32)

			auto proc = GetCurrentProcess();
			HANDLE dst {};

			// note: by default don't let this be inheritable...
			if(!DuplicateHandle(proc, src, proc, &dst, 0, false, DUPLICATE_SAME_ACCESS))
			{
				fprintf(stderr, "DuplicateHandle(): %s\n", GetLastErrorAsString());
				exit(1);
			}

			return dst;

#else
			auto ret = os::FD_NONE;
			if(ret = dup(src); ret < 0)
			{
				fprintf(stderr, "dup(%d): %s\n", src, strerror(errno));
				exit(1);
			}

			// on unix, it is important to make this new pipe also cloexec.
			if(fcntl(ret, F_SETFD, FD_CLOEXEC) < 0)
			{
				fprintf(stderr, "fcntl(): %s\n", os::strerror_wrapper());
				exit(1);
			}

			return ret;
#endif
		}

		inline std::string quote_argument(std::string_view arg)
		{
#if defined(_WIN32)
			// https://docs.microsoft.com/en-gb/archive/blogs/twistylittlepassagesallalike/everyone-quotes-command-line-arguments-the-wrong-way
			if(s.find_first_of(" \t\n\v\f") == std::string::npos)
				return std::string(s);

			std::string ret = "\"";
			int backs = 0;

			for(auto it = s.begin();; ++it)
			{
				int backs = 0;
				while(it != s.end() && *it == '\\')
					++it, ++backs;

				if(it == s.end())
				{
					ret.append(backs * 2, '\\');
					break;
				}
				else if(*it == '"')
				{
					ret.append(backs * 2 + 1, '\\');
					ret.push_back(*it);
				}
				else
				{
					ret.append(backs, '\\');
					ret.push_back(*it);
				}
			}

			ret.push_back('"');
			return ret;
#else
			// on unix, char** argv is passed directly, so unless the program is really stupid, there's
			// actually no need to quote space-containing paths.
			return std::string(arg);
#endif
		}

#if defined(_WIN32)
		inline std::string make_argument_array(const std::string& exec_name, const std::vector<std::string>& args)
		{
			std::string ret = quote_argument(exec_name);
			for(auto& arg : args)
			{
				ret += " ";
				ret += quote_argument(arg);
			}

			return ret;
		}
#else
		inline char** make_argument_array(const std::string& exec_name, const std::vector<std::string>& args)
		{
			char** args_array = new char*[args.size() + 2];
			for(size_t i = 0; i < args.size(); i++)
				args_array[1 + i] = const_cast<char*>(args[i].c_str());

			args_array[0] = const_cast<char*>(exec_name.c_str());
			args_array[args.size() + 1] = nullptr;
			return args_array;
		}
#endif

		inline bool poll_read_output(os::Fd fd, std::string& out, int timeout_ms = 0)
		{
#if defined(_WIN32)
#error "not supported"
#else

			struct pollfd pfd
			{
			};
			pfd.fd = fd;
			pfd.events = POLLIN;

			fprintf(stderr, "POLLING\n");
			int k = poll(&pfd, 1, timeout_ms);
			if(k < 0)
			{
				fprintf(stderr, "poll(%d): %s\n", fd, os::strerror_wrapper());
				return false;
			}

			fprintf(stderr, "POLLED\n");
			if(not(pfd.revents & POLLIN))
				return false;

			fprintf(stderr, "READING\n");
			char buf[4096] {};
			auto did_read = read(fd, &buf[0], 4096);
			fprintf(stderr, "READED\n");
			if(did_read < 0)
			{
				fprintf(stderr, "read(%d): %s\n", fd, os::strerror_wrapper());
				return false;
			}

			out.append(&buf[0], static_cast<size_t>(did_read));
			return k > 0;

#endif
		}
	}

	struct Process
	{
	private:
		Process() { }

	public:
		Process(const Process&) = delete;
		Process& operator=(const Process&) = delete;

		std::string readStdoutLine() { return readline_impl(m_stdout_pipe, m_stdout_buffer); }

		std::string readStderrLine() { return readline_impl(m_stderr_pipe, m_stderr_buffer); }

		std::string readStdout()
		{
			std::string ret {};
			return read_impl(m_stdout_pipe, m_stdout_buffer, ret);
		}

		std::string readStderr()
		{
			std::string ret {};
			return read_impl(m_stderr_pipe, m_stderr_buffer, ret);
		}

		std::string& readStdout(std::string& into)
		{
			read_impl(m_stdout_pipe, m_stdout_buffer, into);
			return into;
		}

		std::string& readStderr(std::string& into)
		{
			read_impl(m_stderr_pipe, m_stderr_buffer, into);
			return into;
		}

		bool pollOutput(std::string& stdout_out, std::string& stderr_out, int timeout = 0)
		{
#if defined(_WIN32)
#error "windows not supported"
#else

			struct pollfd pfds[2] {};
			pfds[0] = { .fd = m_stdout_pipe, .events = POLLIN, .revents = 0 };

			pfds[1] = { .fd = m_stderr_pipe, .events = POLLIN, .revents = 0 };

			int k = poll(&pfds[0], 2, timeout);
			if(k < 0)
			{
				fprintf(stderr, "poll(): %s\n", os::strerror_wrapper());
				exit(1);
			}

			auto read_fd = [](os::Fd fd, std::string& s) {
				char buf[4096] {};
				auto did_read = read(fd, &buf[0], 4096);

				if(did_read < 0)
					fprintf(::stderr, "read(%d): %s\n", fd, os::strerror_wrapper());
				else
					s.append(&buf[0], static_cast<size_t>(did_read));
			};

			if(pfds[0].revents & POLLIN)
				read_fd(m_stdout_pipe, stdout_out);

			if(pfds[1].revents & POLLIN)
				read_fd(m_stderr_pipe, stderr_out);

			return k != 0;

#endif
		}


		void send(std::string_view str)
		{
			if(not fd_valid(m_stdin_pipe))
				return;

			size_t ofs = 0;
			while(ofs < str.size())
			{
				auto did_write = write(m_stdin_pipe, str.data() + ofs, str.size() - ofs);
				if(did_write < 0)
				{
					fprintf(stderr, "write(%d): %s\n", m_stdin_pipe, os::strerror_wrapper());
					return;
				}

				ofs += static_cast<size_t>(did_write);
			}
		}

		void sendLine(std::string_view line)
		{
			this->send(line);
			this->send("\n");
		}

		int wait()
		{
			m_waited = true;
#if defined(_WIN32)
			if(WaitForSingleObject(m_pid, INFINITE) != WAIT_OBJECT_0)
			{
				fprintf(stderr, "WaitForSingleObject(): %s\n", GetLastErrorAsString());
				exit(1);
			}

			DWORD status = 0;
			if(!GetExitCodeProcess(proc.handle, &status))
			{
				fprintf(stderr, "GetExitCodeProcess(): %s\n", GetLastErrorAsString());
				exit(1);
			}

			CloseHandle(m_pid);
			return static_cast<int>(status);
#else
			int status = 0;
		again:
			if(waitpid(m_pid, &status, 0) < 0)
			{
				if(errno == EINTR)
					goto again;

				fprintf(stderr, "waitpid(%d): %s\n", m_pid, strerror(errno));
				exit(1);
			}

			return status;
#endif
		}

		bool isAlive() const
		{
#if defined(_WIN32)
#error "not support"
#else

			int st = 0;
			if(int err = waitpid(m_pid, &st, WNOHANG); err < 0)
			{
				return false;
			}
			else if(err == 0)
			{
				return true;
			}
			else
			{
				m_waited = true;
				return not WIFEXITED(st);
			}
#endif
		}

		void terminate()
		{
			if(m_terminated)
				return;

			m_terminated = true;
			os::close_file(m_stdin_pipe);
			os::close_file(m_stdout_pipe);
			os::close_file(m_stderr_pipe);

#if defined(_WIN32)
			TerminateProcess(m_pid, EXIT_SUCCESS);
#else
			kill(m_pid, SIGKILL);
#endif
		}

		void terminateAll()
		{
			if(m_terminated)
				return;

			m_terminated = true;
			os::close_file(m_stdin_pipe);
			os::close_file(m_stdout_pipe);
			os::close_file(m_stderr_pipe);

#if defined(_WIN32)
			TerminateProcess(m_pid, EXIT_SUCCESS);
#else
			// since we set pgid = gid, this will kill all our children too
			kill(-m_pid, SIGKILL);
#endif
		}

		~Process()
		{
			if(not m_moved)
			{
				this->terminateAll();

				if(not m_waited)
					this->wait();
			}
		}

		Process(Process&& other)
		{
			m_pid = std::move(other.m_pid);
			m_waited = other.m_waited;
			m_terminated = other.m_terminated;
			m_stdin_pipe = std::move(other.m_stdin_pipe);
			m_stdout_pipe = std::move(other.m_stdout_pipe);
			m_stderr_pipe = std::move(other.m_stderr_pipe);
			m_stdout_buffer = std::move(other.m_stdout_buffer);
			m_stderr_buffer = std::move(other.m_stderr_buffer);
			other.m_moved = true;
		}

		Process& operator=(Process&& other)
		{
			if(&other == this)
				return *this;

			m_pid = std::move(other.m_pid);
			m_waited = other.m_waited;
			m_terminated = other.m_terminated;
			m_stdin_pipe = std::move(other.m_stdin_pipe);
			m_stdout_pipe = std::move(other.m_stdout_pipe);
			m_stderr_pipe = std::move(other.m_stderr_pipe);
			m_stdout_buffer = std::move(other.m_stdout_buffer);
			m_stderr_buffer = std::move(other.m_stderr_buffer);
			other.m_moved = true;
			return *this;
		}


	private:
		bool m_moved = false;
		bool m_terminated = false;
		mutable bool m_waited = false;

		os::Pid m_pid {};
		os::Fd m_stdin_pipe {};
		os::Fd m_stdout_pipe {};
		os::Fd m_stderr_pipe {};

		std::string m_stdout_buffer;
		std::string m_stderr_buffer;

		bool fd_valid(os::Fd fd)
		{
#if defined(_WIN32)
#error "not support"
#else
			return fcntl(fd, F_GETFD) >= 0;
#endif
		}

		std::string readline_impl(os::Fd pipe, std::string& partial_buf)
		{
#if defined(_WIN32)

#else
			std::string ret = std::move(partial_buf);
			partial_buf.clear();

			if(not fd_valid(pipe))
				return ret;

			while(true)
			{
				char buf[4096] {};
				auto did_read = read(pipe, &buf[0], 4096);
				if(did_read < 0)
				{
					fprintf(stderr, "read(%d): %s\n", pipe, os::strerror_wrapper());
					return "";
				}
				else if(did_read == 0)
				{
					for(size_t i = 0; i < ret.size(); i++)
					{
						if(ret[i] == '\n')
						{
							partial_buf.append(ret.data() + i + 1, ret.size() - i - 1);
							ret.resize(i);
							break;
						}
					}

					return ret;
				}

				// slow but meh
				for(size_t i = 0; i < static_cast<size_t>(did_read); i++)
				{
					if(buf[i] == '\n')
					{
						ret.append(&buf[0], i);
						partial_buf.append(&buf[i + 1], static_cast<size_t>(did_read) - i - 1);
						return ret;
					}
				}

				// if we didn't return, then just add to the buffer and keep retrying.
				ret.append(&buf[0], static_cast<size_t>(did_read));
			}
#endif
		}

		std::string& read_impl(os::Fd pipe, std::string& partial_buf, std::string& out_str)
		{
			out_str.append(partial_buf);
			partial_buf.clear();

			if(not fd_valid(pipe))
				return out_str;

			char buf[4096] {};
			auto did_read = read(pipe, &buf[0], 4096);

			if(did_read < 0)
			{
				fprintf(stderr, "read(%d): %s\n", pipe, os::strerror_wrapper());
				return out_str;
			}

			out_str.append(&buf[0], static_cast<size_t>(did_read));
			return out_str;
		}

		inline friend std::pair<std::optional<Process>, std::string> runProcess(const std::string& process,
		    const std::vector<std::string>& args,
		    const std::filesystem::path& cwd,
		    bool capture_stdout,
		    bool capture_stderr);

		inline friend std::pair<std::optional<Process>, std::string> runProcess(const std::string& process,
		    const std::vector<std::string>& args,
		    bool capture_stdout,
		    bool capture_stderr);
	};



	inline std::pair<std::optional<Process>, std::string> runProcess(const std::string& process,
	    const std::vector<std::string>& args,
	    const std::filesystem::path& cwd,
	    bool capture_stdout = true,
	    bool capture_stderr = true)
	{
		auto [stdin_pipe_read, stdin_pipe_write] = os::make_pipe();
		auto [stdout_pipe_read, stdout_pipe_write] = os::make_pipe();
		auto [stderr_pipe_read, stderr_pipe_write] = os::make_pipe();

#if defined(_WIN32)

#else

		if(auto child = fork(); child < 0)
		{
			return { std::nullopt, std::string("fork(): ") + os::strerror_wrapper() };
		}
		else if(child == 0)
		{
			os::dupe_fd2(stdin_pipe_read, STDIN_FILENO);
			if(capture_stdout)
				os::dupe_fd2(stdout_pipe_write, STDOUT_FILENO);

			if(capture_stderr)
				os::dupe_fd2(stderr_pipe_write, STDERR_FILENO);

			os::close_file(stdin_pipe_write);
			os::close_file(stdout_pipe_read);
			os::close_file(stderr_pipe_read);

			std::filesystem::current_path(cwd);
			setpgid(getpid(), getpid());

			auto arg_array = os::make_argument_array(process, args);
			if(auto err = execvp(process.c_str(), arg_array); err < 0)
				fprintf(stderr, "execvp(): %s\n", os::strerror_wrapper());

			abort();
		}
		else
		{
			Process proc {};
			proc.m_pid = child;
			proc.m_stdin_pipe = stdin_pipe_write;
			proc.m_stdout_pipe = stdout_pipe_read;
			proc.m_stderr_pipe = stderr_pipe_read;

			os::close_file(stdin_pipe_read);
			os::close_file(stdout_pipe_write);
			os::close_file(stderr_pipe_write);

			return { std::optional { std::move(proc) }, "" };
		}
#endif
	}

	inline std::pair<std::optional<Process>, std::string> runProcess(const std::string& process,
	    const std::vector<std::string>& args,
	    bool capture_stdout = true,
	    bool capture_stderr = true)
	{
		return runProcess(process, args, std::filesystem::current_path(), capture_stdout, capture_stderr);
	}
}
