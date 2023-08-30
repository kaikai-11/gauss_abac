#ifndef ABAC_POLICY_H
#define ABAC_POLICY_H

#include "utils/elog.h"
#include "libpq/libpq-fe.h"
#include "nodes/nodes.h"
#include "parser/abac_sec.h"
#include <ctime>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <math.h>
#include <algorithm>
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
#include "storage/lock/lock.h"
#include "utils/snapmgr.h"
#include "utils/builtins.h"
#include "access/htup.h"
#include "catalog/indexing.h"
#include "access/genam.h"
#include "utils/fmgroids.h"
#include "utils/lsyscache.h"

#define TIME_LENGTH 8
#define DATE_LENGTH 10
#define WEEKDAY_LENGTH 1

typedef struct __ATT
{
	NameData object;
	abacAttManagerObjectType object_type;
	NameData att_name;
	abacAttType att_type;
	NameData att_value;
} ATT, *PATT;

typedef struct __POLICY
{
	NameData name;
	NameData subject;
	NameData object;
	abacPolicyObjectType object_type;
	abacPolicyActionType action;
	NameData att_name;
	NameData const_val;
	abacPolicyOperator policy_operator;
	abacPolicyTag tag;
} GaussPOLICY, *PPOLICY;

bool search_policy(const char *subject,
				   const char *object,
				   const abacAttManagerObjectType &object_type,
				   const abacPolicyActionType &action,
				   PPOLICY *list,
				   size_t &list_length);
abacPolicyActionType get_action(AclMode mask);
abacAttType get_type_by_name_from_att(const char *name);
abacPolicyObjectType get_policy_object_type(Oid object_type_oid);
abacPolicyActionType get_policy_action_type(Oid action_type_oid);
abacPolicyOperator get_policy_operator(Oid operator_oid);
abacPolicyTag get_policy_tag(Oid tag_oid);
int policyDecision(const char *subject, const abacAttManagerObjectType &subject_type,
				   const char *object, const abacAttManagerObjectType &object_type,
				   const GaussPOLICY &policy, const char *s_ip);

#endif // ABAC_POLICY_H
