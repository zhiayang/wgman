pkgname=wgman
pkgver=0.1.0
pkgrel=1
pkgdesc='Simple WireGuard wrapper-manager-thing'
url='https://github.com/zhiayang/wgman'
depends=('python' 'python-click' 'python-psutil' 'python-elevate')
makedepends=('python-pip')
checkdepends=()
license=(Apache)
arch=(any)
source=()
sha256sums=()

build() {
	
}

package() {
  cd "$srcdir"
  PIP_CONFIG_FILE=/dev/null pip install --isolated --root="$pkgdir" --ignore-installed --no-deps *.whl
}
