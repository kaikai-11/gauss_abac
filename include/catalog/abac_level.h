#ifndef ABAC_LEVEL_H
#define ABAC_LEVEL_H

#include "catalog/genbki.h"

#define LevelSecRelationId 3306

CATALOG(abac_level,3306)
{
    NameData name;
    int4 grade;
}FormData_abac_level;

typedef FormData_abac_level* Form_abac_level;

#define Natts_abac_level 2
#define Anum_abac_level_name 1
#define Anum_abac_level_grade 2

DATA(insert ("root" 0));
DATA(insert ("high" 1));
DATA(insert ("normal" 2));
DATA(insert ("low" 3));

#endif