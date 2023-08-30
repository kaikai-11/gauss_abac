#ifndef ABAC_DOMAIN_H
#define ABAC_DOMAIN_H

#include "catalog/genbki.h"

#define DomainSecRelationId 3307

CATALOG(abac_domain,3307)
{
    int4 id;
    NameData name;
    int4 rid;
}FormData_abac_domain;

typedef FormData_abac_domain* Form_abac_domain;

#define Natts_abac_domain 3
#define Anum_abac_domain_id 1
#define Anum_abac_domain_name 2
#define Anum_abac_domain_rid 3

DATA(insert (0 "root" -1));
DATA(insert (1 "audit" 0));
DATA(insert (2 "sec" 0));
DATA(insert (3 "admin" 0));


#endif