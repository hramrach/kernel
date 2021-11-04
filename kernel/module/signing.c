// SPDX-License-Identifier: GPL-2.0-or-later
/* Module signature checker
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/module_signature.h>
#include <linux/string.h>
#include <linux/verification.h>
#include <linux/security.h>
#include <crypto/public_key.h>
#include <uapi/linux/module.h>
#include "internal.h"

#undef MODULE_PARAM_PREFIX
#define MODULE_PARAM_PREFIX "module."

static bool sig_enforce = IS_ENABLED(CONFIG_MODULE_SIG_FORCE);
module_param(sig_enforce, bool_enable_only, 0644);

/*
 * Export sig_enforce kernel cmdline parameter to allow other subsystems rely
 * on that instead of directly to CONFIG_MODULE_SIG_FORCE config.
 */
bool is_module_sig_enforced(void)
{
	return sig_enforce;
}
EXPORT_SYMBOL(is_module_sig_enforced);

void set_module_sig_enforced(void)
{
	sig_enforce = true;
}

/**
 * verify_appended_signature - Verify the signature on a module
 * @data: The data to be verified
 * @len: Size of @data.
 * @trusted_keys: Keyring to use for verification
 * @purpose: The use to which the key is being put
 */
int verify_appended_signature(const void *data, unsigned long *len,
			      struct key *trusted_keys,
			      enum key_being_used_for purpose)
{
	unsigned long sig_len;
	int ret;

	pr_devel("==>%s %s(,%lu)\n", __func__, key_being_used_for[purpose], *len);

	ret = mod_parse_sig(data, len, &sig_len, key_being_used_for[purpose]);
	if (ret)
		return ret;

	return verify_pkcs7_signature(data, *len, data + *len, sig_len,
				      trusted_keys,
				      purpose,
				      NULL, NULL);
}

int module_sig_check(struct load_info *info, int flags)
{
	int err = -ENODATA;
	const char *reason;
	const void *mod = info->hdr;
	bool mangled_module = flags & (MODULE_INIT_IGNORE_MODVERSIONS |
				       MODULE_INIT_IGNORE_VERMAGIC);
	/*
	 * Do not allow mangled modules as a module with version information
	 * removed is no longer the module that was signed.
	 */
	if (!mangled_module) {
		err = verify_appended_signature(mod, &info->len,
						VERIFY_USE_SECONDARY_KEYRING,
						VERIFYING_MODULE_SIGNATURE);
		if (!err) {
			info->sig_ok = true;
			return 0;
		}
	}

	/*
	 * We don't permit modules to be loaded into the trusted kernels
	 * without a valid signature on them, but if we're not enforcing,
	 * certain errors are non-fatal.
	 */
	switch (err) {
	case -ENODATA:
		reason = "unsigned module";
		break;
	case -ENOPKG:
		reason = "module with unsupported crypto";
		break;
	case -ENOKEY:
		reason = "module with unavailable key";
		break;

	default:
		/*
		 * All other errors are fatal, including lack of memory,
		 * unparseable signatures, and signature check failures --
		 * even if signatures aren't required.
		 */
		return err;
	}

	if (is_module_sig_enforced()) {
		pr_notice("Loading of %s is rejected\n", reason);
		return -EKEYREJECTED;
	}

	return security_locked_down(LOCKDOWN_MODULE_SIGNATURE);
}
