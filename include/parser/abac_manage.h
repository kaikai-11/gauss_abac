#ifndef ABAC_MANAGE_H
#define ABAC_MANAGE_H
#include <stdio.h>
#include <stdlib.h>
#include "knl/knl_session.h"
#include "commands/dbcommands.h"
#include "miscadmin.h"
#include "utils/lsyscache.h"
#include "parser/abac_policy.h"
#include "parser/abac_sec.h"
#include "postgres.h"
#include "utils/rel.h"
#include "utils/relcache.h"
#include "access/heapam.h"
#include "utils/syscache.h"
#include "catalog/abac_level.h"
#include "catalog/abac_domain.h"
#include "catalog/abac_policies.h"
#include "catalog/abac_attributes.h"
#include "catalog/abac_attributes_manager.h"
#include "catalog/pg_type.h"
#include "catalog/pg_authid.h"
#include "catalog/dependency.h"
#include "catalog/pg_depend.h"
#include "storage/lock/lock.h"
#include "utils/snapmgr.h"
#include "utils/builtins.h"
#include "access/htup.h"
#include "catalog/indexing.h"
#include "access/genam.h"
#include "utils/fmgroids.h"

bool abac_create_level(const char *name_old, const char *name_new);
bool abac_drop_level(const char *name);

bool abac_create_domain(const char *name_old, const char *name_new);
bool abac_drop_domain(const char *name);

bool abac_create_policy(const char *name,
						const char *subject,
						const char *object,
						const char *object_type,
						const char *action,
						const char *att_name,
						const char *const_val,
						const char *policy_operator,
						const char *tag,
						bool enable);
bool abac_drop_policy(const char *name);
bool abac_alter_policy_on(const char *name);
bool abac_alter_policy_off(const char *name);

bool abac_create_attribute(const char *name, const char *type);
bool abac_drop_attribute(const char *name);

bool abac_grant_attribute(const char *name, const char *value, const char *object, const char *object_type);
bool abac_revoke_attribute(const char *name, const char *value, const char *object, const char *object_type);

bool check_database_sign(Oid db_oid, Oid roleid, AclMode mode);
bool check_namespace_sign(Oid namespace_oid, Oid roleid, AclMode mode);
bool check_table_sign(Oid table_oid, Oid roleid, AclMode mode);
bool check_attribute_sign(Oid table_oid, AttrNumber attnum, Oid roleid, AclMode mode);

#endif // ABAC_MANAGE_H
