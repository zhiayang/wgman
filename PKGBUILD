pkgname=wgman
pkgver=0.1.0
pkgrel=1
pkgdesc='Simple WireGuard wrapper-manager-thing'
url='https://github.com/zhiayang/wgman'
depends=('python' 'python-click' 'python-psutil' 'python-elevate')
makedepends=('python-installer' 'python-build')
checkdepends=()
license=(Apache)
arch=('any')
_commit=asdf
source=('git+https://github.com/macos-pacman/pmutils.git#commit=${_commit}')
sha256sums=('SKIP')

build() {
	cd wgman
	python -m build --wheel --no-isolation
}

package() {
	cd wgman
	python -m installer --destdir="$pkgdir" dist/*.whl
}
