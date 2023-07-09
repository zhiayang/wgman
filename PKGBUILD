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
_commit='30edf45971f4d75528d5c55212d6e23e39736cb1'
source=('git+https://github.com/zhiayang/wgman.git#commit=${_commit}')
sha256sums=('SKIP')

build() {
	cd wgman
	python -m build --wheel --no-isolation
}

package() {
	cd wgman
	python -m installer --destdir="$pkgdir" dist/*.whl
}
