#include "parser/abac_sec.h"

bool get_grade_by_name_from_level(const char *name, int4 *grade)
{
	Relation rel = NULL;
	TableScanDesc scan = NULL;
	HeapTuple tuple = NULL;
	Form_abac_level level_sec_form = NULL;
	rel = heap_open(LevelSecRelationId, AccessShareLock);
	scan = heap_beginscan(rel, SnapshotNow, 0, NULL);

	bool ret = false;

	while ((tuple = heap_getnext(scan, ForwardScanDirection)) != NULL)
	{
		level_sec_form = (Form_abac_level)GETSTRUCT(tuple);
		if (!strcmp(NameStr(level_sec_form->name), name))
		{
			if (grade != NULL)
				*grade = level_sec_form->grade;
			ret = true;
			break;
		}
	}
	heap_endscan(scan);
	heap_close(rel, AccessShareLock);
	return ret;
}

void insert_level(int4 grade, const char *name)
{
	Datum values[Natts_abac_level];
	bool nulls[Natts_abac_level];
	Relation rel = NULL;
	HeapTuple tuple = NULL;
	NameData level_name;
	errno_t errorno = EOK;

	errorno = memset_s(values, sizeof(values), 0, sizeof(values));
	securec_check_c(errorno, "\0", "\0");

	errorno = memset_s(nulls, sizeof(nulls), 0, sizeof(nulls));
	securec_check_c(errorno, "\0", "\0");

	if(-1 == namestrcpy(&level_name, name))
		ereport(ERROR, (errmsg("The name of level is invalid.")));

	values[Anum_abac_level_grade - 1] = Int32GetDatum(grade);
	values[Anum_abac_level_name - 1] = NameGetDatum(&level_name);

	rel = heap_open(LevelSecRelationId, RowExclusiveLock);
	tuple = heap_form_tuple(RelationGetDescr(rel), values, nulls);

	(void)simple_heap_insert(rel, tuple);
	CatalogUpdateIndexes(rel, tuple);

	heap_freetuple_ext(tuple);
	heap_close(rel, RowExclusiveLock);
}

void delete_level(int4 grade)
{
	Relation rel = NULL;
	ScanKeyData skey[1];
	SysScanDesc scan = NULL;
	HeapTuple tuple = NULL;

	rel = heap_open(LevelSecRelationId, RowExclusiveLock);

	ScanKeyInit(&skey[0],
				Anum_abac_level_grade,
				BTEqualStrategyNumber,
				F_OIDEQ,
				ObjectIdGetDatum(grade));
	scan = systable_beginscan(rel,
							  AbacLevelGradeIndexId,
							  true,
							  NULL,
							  1,
							  skey);
	tuple = systable_getnext(scan);
	if (!HeapTupleIsValid(tuple))
	{
		ereport(ERROR, (errmsg("Could not find tuple.")));
	}
	simple_heap_delete(rel, &tuple->t_self);
	systable_endscan(scan);
	heap_close(rel, RowExclusiveLock);
}

void update_level_grade(int4 grade_old, int4 grade_new)
{
	Datum values[Natts_abac_level];
	bool nulls[Natts_abac_level];
	bool replaces[Natts_abac_level];
	Relation rel = NULL;
	HeapTuple tuple = NULL, new_tuple = NULL;
	memset_s(values, sizeof(values), 0, sizeof(values));
	memset_s(nulls, sizeof(nulls), 0, sizeof(nulls));
	memset_s(replaces, sizeof(replaces), 0, sizeof(replaces));

	replaces[Anum_abac_level_grade - 1] = true;
	values[Anum_abac_level_grade - 1] = ObjectIdGetDatum(grade_new);
	replaces[Anum_abac_level_name - 1] = false;

	rel = heap_open(LevelSecRelationId, RowExclusiveLock);

	tuple = SearchSysCache1(ABACLEVELGRADE, ObjectIdGetDatum(grade_old));
	if (!HeapTupleIsValid(tuple))
	{
		ereport(ERROR, (errmsg("Could not find tuple.")));
	}
	new_tuple = heap_modify_tuple(tuple, RelationGetDescr(rel), values, nulls, replaces);
	simple_heap_update(rel, &new_tuple->t_self, new_tuple);
	CatalogUpdateIndexes(rel, new_tuple);
	ReleaseSysCache(tuple);
	heap_close(rel, RowExclusiveLock);
}

int levelcmp(const char *name_left, const char *name_right)
{
	bool ret = false;
	int4 grade_left = 0, grade_right = 0;

	ret = get_grade_by_name_from_level(name_left, &grade_left);
	if (ret == false)
		return -2;
	ret = get_grade_by_name_from_level(name_right, &grade_right);
	if (ret == false)
		return -2;
	if (grade_left < grade_right)
		return 1;
	else if (grade_left == grade_right)
		return 0;
	else
		return -1;
}

bool get_domain_by_name(const char *name, int4 *id, int4 *rid)
{
	Relation rel = NULL;
	TableScanDesc scan = NULL;
	HeapTuple tuple = NULL;
	Form_abac_domain domain_sec_form = NULL;
	rel = heap_open(DomainSecRelationId, AccessShareLock);
	scan = heap_beginscan(rel, SnapshotNow, 0, NULL);

	bool ret = false;

	while ((tuple = heap_getnext(scan, ForwardScanDirection)) != NULL)
	{
		domain_sec_form = (Form_abac_domain)GETSTRUCT(tuple);
		if (!strcmp(NameStr(domain_sec_form->name), name))
		{
			if (id != NULL)
				*id = domain_sec_form->id;
			if (rid != NULL)
				*rid = domain_sec_form->rid;
			ret = true;
			break;
		}
	}
	heap_endscan(scan);
	heap_close(rel, AccessShareLock);
	return ret;
}

bool get_domain_by_id(int4 id, int4 *rid)
{
	HeapTuple tuple =
		SearchSysCache1(ABACDOMAINID,
						ObjectIdGetDatum(id));
	if (!HeapTupleIsValid(tuple))
		return false;
	if (rid != NULL)
		*rid = ((Form_abac_domain)GETSTRUCT(tuple))->rid;
	ReleaseSysCache(tuple);
	return true;
}

void insert_domain(int4 id, const char *name, int4 rid)
{
	Datum values[Natts_abac_domain];
	bool nulls[Natts_abac_domain];
	Relation rel = NULL;
	HeapTuple tuple = NULL;
	NameData domain_name;

	error_t errorno = EOK;

	errorno = memset_s(values, sizeof(values), 0, sizeof(values));
	securec_check_c(errorno, "\0", "\0");

	errorno = memset_s(nulls, sizeof(nulls), 0, sizeof(nulls));
	securec_check_c(errorno, "\0", "\0");

	if (-1 == namestrcpy(&domain_name, name))
		ereport(ERROR, (errmsg("The name of domain is invalid.")));

	values[Anum_abac_domain_id - 1] = Int32GetDatum(id);
	values[Anum_abac_domain_name - 1] = NameGetDatum(&domain_name);
	values[Anum_abac_domain_rid - 1] = Int32GetDatum(rid);

	rel = heap_open(DomainSecRelationId, RowExclusiveLock);
	tuple = heap_form_tuple(RelationGetDescr(rel), values, nulls);

	(void)simple_heap_insert(rel, tuple);
	CatalogUpdateIndexes(rel, tuple);

	heap_freetuple_ext(tuple);
	heap_close(rel, RowExclusiveLock);
}

void delete_domain(int4 id)
{
	Relation rel = NULL;
	ScanKeyData skey[1];
	SysScanDesc scan = NULL;
	HeapTuple tuple = NULL;

	rel = heap_open(DomainSecRelationId, RowExclusiveLock);

	ScanKeyInit(&skey[0],
				Anum_abac_domain_id,
				BTEqualStrategyNumber,
				F_OIDEQ,
				ObjectIdGetDatum(id));
	scan = systable_beginscan(rel,
							  AbacDomainIdIndexId,
							  true,
							  NULL,
							  1,
							  skey);
	tuple = systable_getnext(scan);
	if (!HeapTupleIsValid(tuple))
	{
		ereport(ERROR, (errmsg("Could not find tuple.")));
	}
	simple_heap_delete(rel, &tuple->t_self);
	systable_endscan(scan);
	heap_close(rel, RowExclusiveLock);
}

bool domain_have_child(int4 id)
{
	Relation rel = NULL;
	TableScanDesc scan = NULL;
	HeapTuple tuple = NULL;
	Form_abac_domain domain_sec_form = NULL;
	rel = heap_open(DomainSecRelationId, AccessShareLock);
	scan = heap_beginscan(rel, SnapshotNow, 0, NULL);

	while ((tuple = heap_getnext(scan, ForwardScanDirection)) != NULL)
	{
		domain_sec_form = (Form_abac_domain)GETSTRUCT(tuple);
		if (domain_sec_form->rid == id)
			return true;
	}
	heap_endscan(scan);
	heap_close(rel, AccessShareLock);
	return false;
}

bool domain_is_bigger(int4 id_left, int4 id_right)
{
	int4 rid_right = 0;
	get_domain_by_id(id_right, &rid_right);
	while (rid_right != -1)
	{
		if (rid_right == id_left)
			return true;
		id_right = rid_right;
		get_domain_by_id(id_right, &rid_right);
	}
	return false;
}

int domaincmp(const char *name_left, const char *name_right)
{
	bool ret = false;
	int4 id_left = 0, id_right = 0;
	ret = get_domain_by_name(name_left, &id_left, NULL);
	if (ret == false)
		return -2;
	ret = get_domain_by_name(name_right, &id_right, NULL);
	if (ret == false)
		return -2;
	if (id_left == id_right)
		return 0;
	if (domain_is_bigger(id_left, id_right))
		return 1;
	if (domain_is_bigger(id_right, id_left))
		return -1;
	return -3;
}
