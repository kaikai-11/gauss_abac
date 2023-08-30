#ifndef ABAC_ATTRIBUTES_MANAGER_H
#define ABAC_ATTRIBUTES_MANAGER_H

#include "catalog/genbki.h"

#define AttributesManagerRelationId 3310

typedef enum abacAttManagerObjectType {
    ABAC_ATTMANAGER_OBJECT_TYPE_DATABASE = 1,
    ABAC_ATTMANAGER_OBJECT_TYPE_SCHEMA,
    ABAC_ATTMANAGER_OBJECT_TYPE_TABLE,
    ABAC_ATTMANAGER_OBJECT_TYPE_COLUMN,
    ABAC_ATTMANAGER_OBJECT_TYPE_USER,
} abacAttManagerObjectType;

CATALOG(abac_attributes_manager,3310)
{
    NameData object;
    abacAttManagerObjectType object_type;
    NameData attribute_name;
    NameData attribute_value;
}FormData_abac_attributes_manager;

typedef FormData_abac_attributes_manager* Form_abac_attributes_manager;

#define Natts_abac_attributes_manager 4
#define Anum_abac_attributes_manager_object 1
#define Anum_abac_attributes_manager_object_type 2
#define Anum_abac_attributes_manager_attribute_name 3
#define Anum_abac_attributes_manager_attribute_value 4


DATA(insert ("omm" USER "level" "root"));
DATA(insert ("omm" USER "domain" "root"));
DATA(insert ("pg_catalog" SCHEMA "level" "high"));
DATA(insert ("pg_catalog" SCHEMA "domain" "sec"));
DATA(insert ("pg_catalog.abac_level" TABLE "level" "high"));
DATA(insert ("pg_catalog.abac_level" TABLE "domain" "sec"));
DATA(insert ("pg_catalog.abac_domain" TABLE "level" "high"));
DATA(insert ("pg_catalog.abac_domain" TABLE "domain" "sec"));
DATA(insert ("pg_catalog.abac_attributes" TABLE "level" "high"));
DATA(insert ("pg_catalog.abac_attributes" TABLE "domain" "sec"));
DATA(insert ("pg_catalog.abac_attributes_manager" TABLE "level" "high"));
DATA(insert ("pg_catalog.abac_attributes_manager" TABLE "domain" "sec"));
DATA(insert ("pg_catalog.abac_policies" TABLE "level"  "high"));
DATA(insert ("pg_catalog.abac_policies" TABLE "domain" "sec"));


#endif
