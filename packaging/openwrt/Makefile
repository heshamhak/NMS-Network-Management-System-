include $(TOPDIR)/rules.mk

PKG_NAME:=nms-console
PKG_VERSION:=5.0.0
PKG_RELEASE:=1

PKG_MAINTAINER:=Hesham Amjad <heshamhak@users.noreply.github.com>
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE

PKG_ARCH:=all
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

define Package/nms-console
  SECTION:=admin
  CATEGORY:=Administration
  TITLE:=NMS Network Management System Console
  URL:=https://github.com/heshamhak/NMS-Network-Management-System-
  PKGARCH:=all
  DEPENDS:=+ucode +ucode-mod-fs +ucode-mod-ubus +ucode-mod-uci +ucode-mod-socket +ucode-mod-math +ucode-mod-struct +ucode-mod-uloop +ucode-mod-digest
endef

define Package/nms-console/description
  Open-source bilingual (EN/AR) network management and monitoring console
  for OpenWrt routers with privilege-separated noc-apid and noc-helperd daemons.
endef

define Package/nms-console/conffiles
/etc/noc-console/
endef

define Build/Compile
	true
endef

define Package/nms-console/preinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && R="$${IPKG_INSTROOT}" || R=""
ETC_DIR="$${R}/etc/noc-console"
INIT_DIR="$${R}/etc/init.d"
MANIFEST="$${ETC_DIR}/installed_files.manifest"
MIG_DIR="$${ETC_DIR}/.pkg_migration_backup"
MIG_STATE="$${ETC_DIR}/.pkg_migration_state"

if [ -z "$${IPKG_INSTROOT}" ]; then
	[ -x "$${INIT_DIR}/noc-apid" ] && "$${INIT_DIR}/noc-apid" stop >/dev/null 2>&1 || true
	[ -x "$${INIT_DIR}/noc-helperd" ] && "$${INIT_DIR}/noc-helperd" stop >/dev/null 2>&1 || true
fi

if [ -f "$${MANIFEST}" ]; then
	mkdir -p "$${MIG_DIR}"
	chmod 0700 "$${MIG_DIR}" 2>/dev/null || true
	while IFS= read -r rel_path || [ -n "$${rel_path}" ]; do
		[ -z "$${rel_path}" ] && continue
		src="$${R}/$${rel_path#/}"
		if [ -f "$${src}" ] && [ ! -L "$${src}" ]; then
			dst="$${MIG_DIR}/$${rel_path#/}"
			mkdir -p "$$(dirname "$${dst}")"
			cp -p "$${src}" "$${dst}" 2>/dev/null || true
		fi
	done < "$${MANIFEST}"
	printf 'status=in_progress\nmanager=opkg\n' > "$${MIG_STATE}"
	chmod 0600 "$${MIG_STATE}" 2>/dev/null || true
fi
exit 0
endef

define Package/nms-console/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && R="$${IPKG_INSTROOT}" || R=""
ETC_DIR="$${R}/etc/noc-console"
RUN_DIR="$${R}/tmp/noc-console"
INIT_DIR="$${R}/etc/init.d"
LIBEXEC_DIR="$${R}/usr/libexec"
MANIFEST="$${ETC_DIR}/installed_files.manifest"
MIG_DIR="$${ETC_DIR}/.pkg_migration_backup"
MIG_STATE="$${ETC_DIR}/.pkg_migration_state"

mkdir -p "$${ETC_DIR}" "$${RUN_DIR}"
chmod 0700 "$${ETC_DIR}" "$${RUN_DIR}" 2>/dev/null || true
chmod 0755 "$${LIBEXEC_DIR}/noc-apid" "$${LIBEXEC_DIR}/noc-helperd" "$${INIT_DIR}/noc-apid" "$${INIT_DIR}/noc-helperd" 2>/dev/null || true

if [ -f "$${MIG_STATE}" ]; then
	rm -rf "$${MIG_DIR}" 2>/dev/null || true
	[ -f "$${MANIFEST}" ] && mv -f "$${MANIFEST}" "$${MANIFEST}.migrated" 2>/dev/null || true
	printf 'status=migrated\nmanager=opkg\n' > "$${MIG_STATE}"
	chmod 0600 "$${MIG_STATE}" 2>/dev/null || true
fi

if [ -z "$${IPKG_INSTROOT}" ] && [ -d /proc/1 ]; then
	"$${INIT_DIR}/noc-helperd" enable >/dev/null 2>&1 || true
	"$${INIT_DIR}/noc-apid" enable >/dev/null 2>&1 || true
	"$${INIT_DIR}/noc-helperd" restart >/dev/null 2>&1 || true
	"$${INIT_DIR}/noc-apid" restart >/dev/null 2>&1 || true
fi
exit 0
endef

define Package/nms-console/prerm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && R="$${IPKG_INSTROOT}" || R=""
INIT_DIR="$${R}/etc/init.d"
if [ -z "$${IPKG_INSTROOT}" ] && [ "$${PKG_UPGRADE:-0}" != "1" ]; then
	[ -x "$${INIT_DIR}/noc-apid" ] && "$${INIT_DIR}/noc-apid" stop >/dev/null 2>&1 || true
	[ -x "$${INIT_DIR}/noc-helperd" ] && "$${INIT_DIR}/noc-helperd" stop >/dev/null 2>&1 || true
	[ -x "$${INIT_DIR}/noc-apid" ] && "$${INIT_DIR}/noc-apid" disable >/dev/null 2>&1 || true
	[ -x "$${INIT_DIR}/noc-helperd" ] && "$${INIT_DIR}/noc-helperd" disable >/dev/null 2>&1 || true
fi
exit 0
endef

define Package/nms-console/install
	$(INSTALL_DIR) $(1)/www/pro
	$(CP) $(PKG_BUILD_DIR)/frontend/* $(1)/www/pro/
	$(INSTALL_DIR) $(1)/usr/libexec
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/backend/noc-apid $(1)/usr/libexec/noc-apid
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/backend/noc-helperd $(1)/usr/libexec/noc-helperd
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/backend/nms_*.uc $(1)/usr/libexec/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/init.d/noc-apid $(1)/etc/init.d/noc-apid
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/init.d/noc-helperd $(1)/etc/init.d/noc-helperd
	$(INSTALL_DIR) $(1)/etc/noc-console
endef

$(eval $(call BuildPackage,nms-console))
