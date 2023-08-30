#ifndef ABAC_ATTRIBUTES_H
#define ABAC_ATTRIBUTES_H

#include "catalog/genbki.h"

#define AttributesRelationId 3309

typedef enum abacAttType
{
	ABAC_ATT_INT,
	ABAC_ATT_DOUBLE,
	ABAC_ATT_STRING,
	ABAC_ATT_DATE,
	ABAC_ATT_DATETIME,
	ABAC_ATT_SET,
	ABAC_ATT_BOOL
} abacAttType;

CATALOG(abac_attributes,3309)
{
    NameData name;
    abacAttType type;
}FormData_abac_attributes;

typedef FormData_abac_attributes* Form_abac_attributes;

#define Natts_abac_attributes 2
#define Anum_abac_attributes_name 1
#define Anum_abac_attributes_type 2

DATA(insert ("level" STRING));
DATA(insert ("domain" SET));
DATA(insert ("ip" STRING));
DATA(insert ("date" DATE));
DATA(insert ("time" DATETIME));
DATA(insert ("weekday" INT));

#endif
