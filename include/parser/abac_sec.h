#ifndef ABAC_SEC_H
#define ABAC_SEC_H

#include "postgres.h"
#include "utils/rel.h"
#include "utils/relcache.h"
#include "access/heapam.h"
#include "utils/syscache.h"
#include "catalog/abac_level.h"
#include "catalog/abac_domain.h"
#include "storage/lock/lock.h"
#include "utils/snapmgr.h"
#include "utils/builtins.h"
#include "access/htup.h"
#include "catalog/indexing.h"
#include "access/genam.h"
#include "utils/fmgroids.h"

bool get_grade_by_name_from_level(const char *name, int4 *grade);
void insert_level(int4 grade, const char *name);
void delete_level(int4 grade);
void update_level_grade(int4 grade_old, int4 grade_new);
int levelcmp(const char *name_left, const char *name_right);

bool get_domain_by_name(const char *name, int4 *id, int4 *rid);
bool get_domain_by_id(int4 id, int4 *rid);
void insert_domain(int4 id, const char *name, int4 rid);
void delete_domain(int4 id);
bool domain_have_child(int4 id);
bool domain_is_bigger(int4 id_left, int4 id_right);
int domaincmp(const char *name_left, const char *name_right);

#endif // ABAC_SEC_H
