pkgname=wgman
pkgver=0.2.2
pkgrel=1
pkgdesc='Simple WireGuard wrapper-manager-thing'
url='https://github.com/zhiayang/wgman'
depends=('wireguard-tools')
makedepends=()
checkdepends=()
license=(Apache)
arch=('any')
_commit='681e37454135990706bddf6445f1b8a012320572'
source=("git+https://github.com/zhiayang/wgman.git#commit=${_commit}")
sha256sums=('SKIP')

build() {
	cd wgman
	make build
}

package() {
	cd wgman
	install -Dm755 build/wgman "$pkgdir"/usr/bin/wgman
}
