#ifndef ABAC_POLICIES_H
#define ABAC_POLICIES_H

#include "catalog/genbki.h"

#define PolicysRelationId 3308

typedef enum abacPolicyObjectType {
    ABAC_POLICY_OBJECT_TYPE_ANY,
    ABAC_POLICY_OBJECT_TYPE_DATABASE,
    ABAC_POLICY_OBJECT_TYPE_SCHEMA,
    ABAC_POLICY_OBJECT_TYPE_TABLE,
    ABAC_POLICY_OBJECT_TYPE_COLUMN,
} abacPolicyObjectType;

typedef enum abacPolicyActionType {
    ABAC_POLICY_ACTION_TYPE_ANY = 0,
    ABAC_POLICY_ACTION_TYPE_SELECT = 1,
    ABAC_POLICY_ACTION_TYPE_INSERT = 2,
    ABAC_POLICY_ACTION_TYPE_UPDATE = 4,
    ABAC_POLICY_ACTION_TYPE_DELETE = 8,
} abacPolicyActionType;

typedef enum abacPolicyOperator {
    ABAC_POLICY_OPERATOR_CONTAIN,
    ABAC_POLICY_OPERATOR_NOT_CONTAIN,
    ABAC_POLICY_OPERATOR_EQ,
    ABAC_POLICY_OPERATOR_LT,
    ABAC_POLICY_OPERATOR_NE,
    ABAC_POLICY_OPERATOR_LE,
    ABAC_POLICY_OPERATOR_GT,
    ABAC_POLICY_OPERATOR_GE,
    ABAC_POLICY_OPERATOR_LIKE,
} abacPolicyOperator;

typedef enum abacPolicyTag {
    ABAC_POLICY_TAG_ATTRIBUTE_ATTRIBUTE,
    ABAC_POLICY_TAG_ATTRIBUTE_VALUE,
    ABAC_POLICY_TAG_ENVIRONMENT_VALUE,
} abacPolicyTag;


CATALOG(abac_policies,3308)
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
    bool enable;
}FormData_abac_policies;

typedef FormData_abac_policies* Form_abac_policies;

#define Natts_abac_policies 10
#define Anum_abac_policies_name 1
#define Anum_abac_policies_subject 2
#define Anum_abac_policies_object 3
#define Anum_abac_policies_object_type 4
#define Anum_abac_policies_action 5
#define Anum_abac_policies_att_name 6
#define Anum_abac_policies_const_val 7
#define Anum_abac_policies_policy_operator 8
#define Anum_abac_policies_tag 9
#define Anum_abac_policies_enable 10

DATA(insert ("default_level" "any" "any" ANY ANY "level" "" GE ATTRIBUTE_ATTRIBUTE t));
DATA(insert ("default_domain" "any" "any" ANY ANY "domain" "" CONTAIN ATTRIBUTE_ATTRIBUTE t));

#endif
