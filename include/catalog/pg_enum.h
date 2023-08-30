/* -------------------------------------------------------------------------
 *
 * pg_enum.h
 *      definition of the system "enum" relation (pg_enum)
 *      along with the relation's initial contents.
 *
 *
 * Copyright (c) 2006-2012, PostgreSQL Global Development Group
 *
 * src/include/catalog/pg_enum.h
 *
 * NOTES
 *      the genbki.pl script reads this file and generates .bki
 *      information from the DATA() statements.
 *
 *      XXX do NOT break up DATA() statements into multiple lines!
 *          the scripts are not as smart as you might think...
 *
 * -------------------------------------------------------------------------
 */
#ifndef PG_ENUM_H
#define PG_ENUM_H

#include "catalog/genbki.h"
#include "nodes/pg_list.h"

/* ----------------
 *        pg_enum definition.  cpp turns this into
 *        typedef struct FormData_pg_enum
 * ----------------
 */
#define EnumRelationId    3501
#define EnumRelation_Rowtype_Id 11628

CATALOG(pg_enum,3501) BKI_SCHEMA_MACRO
{
    Oid         enumtypid;        /* OID of owning enum type */
    float4      enumsortorder;    /* sort position of this enum value */
    NameData    enumlabel;        /* text representation of enum value */
} FormData_pg_enum;

/* ----------------
 *        Form_pg_enum corresponds to a pointer to a tuple with
 *        the format of pg_enum relation.
 * ----------------
 */
typedef FormData_pg_enum *Form_pg_enum;

/* ----------------
 *        compiler constants for pg_enum
 * ----------------
 */
#define Natts_pg_enum                     3
#define Anum_pg_enum_enumtypid            1
#define Anum_pg_enum_enumsortorder        2
#define Anum_pg_enum_enumlabel            3

/* ----------------
 *        pg_enum has no initial contents
 * ----------------
 */
DATA(insert (4473 1 INT));
DATA(insert (4473 2 DOUBLE));
DATA(insert (4473 3 STRING));
DATA(insert (4473 4 DATE));
DATA(insert (4473 5 DATETIME));
DATA(insert (4473 6 SET));
DATA(insert (4473 7 BOOL));

DATA(insert (4475 1 DATABASE));
DATA(insert (4475 2 SCHEMA));
DATA(insert (4475 3 TABLE));
DATA(insert (4475 4 COLUMN));
DATA(insert (4475 5 USER));

DATA(insert (4477 1 ANY));
DATA(insert (4477 2 DATABASE));
DATA(insert (4477 3 SCHEMA));
DATA(insert (4477 4 TABLE));
DATA(insert (4477 5 COLUMN));

DATA(insert (4479 1 ANY));
DATA(insert (4479 2 SELECT));
DATA(insert (4479 3 INSERT));
DATA(insert (4479 4 UPDATE));
DATA(insert (4479 5 DELETE));

DATA(insert (4481 1 CONTAIN));
DATA(insert (4481 2 NOT_CONTAIN));
DATA(insert (4481 3 EQ));
DATA(insert (4481 4 LT));
DATA(insert (4481 5 NE));
DATA(insert (4481 6 LE));
DATA(insert (4481 7 GT));
DATA(insert (4481 8 GE));
DATA(insert (4481 9 LIKE));

DATA(insert (4483 1 ATTRIBUTE_ATTRIBUTE));
DATA(insert (4483 2 ATTRIBUTE_VALUE));
DATA(insert (4483 3 ENVIRONMENT_VALUE));

/*
 * prototypes for functions in pg_enum.c
 */
extern void EnumValuesCreate(Oid enumTypeOid, List *vals);
extern void EnumValuesDelete(Oid enumTypeOid);
extern void AddEnumLabel(Oid enumTypeOid, const char *newVal,
                         const char *neighbor, bool newValIsAfter,
                         bool skipIfExists);
extern void RenameEnumLabel(Oid enumTypeOid, const char *oldVal, const char *newVal);

#endif   /* PG_ENUM_H */

