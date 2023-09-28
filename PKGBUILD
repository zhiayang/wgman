# Maintainer: zhiayang <zhiayang@nowhere>

pkgname=wgman
pkgver=0.5.0
pkgrel=1
pkgdesc='Simple WireGuard wrapper-manager-thing'
url='https://github.com/zhiayang/wgman'
depends=('wireguard-tools' 'libcap')
makedepends=()
checkdepends=()
license=(Apache)
arch=('any')
_commit='a16661345af621281980667beb34df87b057c959'
source=("git+https://github.com/zhiayang/wgman.git#commit=${_commit}")
sha256sums=('SKIP')

_pacman_root=${pacman_root:-}

build() {
	cd wgman
	make build PREFIX=${_pacman_root}
}

package() {
	cd wgman
	install -Dm755 build/wgman "$pkgdir"/${_pacman_root}/usr/bin/wgman

	mkdir -p "$pkgdir"/${_pacman_root}/etc/wgman/

	if [ $(uname) = "Linux" ]; then
		install -Dm755 wgman.target "$pkgdir"/${_pacman_root}/usr/lib/systemd/system/wgman.target
		install -Dm755 wgman@.service "$pkgdir"/${_pacman_root}/usr/lib/systemd/system/wgman@.service
	fi
}
