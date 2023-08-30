#include "parser/abac_manage.h"

static int4 get_level_length()
{
	int4 gs_level_length = 0;
	Relation rel = NULL;
	TableScanDesc scan = NULL;
	HeapTuple tuple = NULL;
	rel = heap_open(LevelSecRelationId, AccessShareLock);
	scan = heap_beginscan(rel, SnapshotNow, 0, NULL);

	while ((tuple = heap_getnext(scan, ForwardScanDirection)) != NULL)
		++gs_level_length;

	heap_endscan(scan);
	heap_close(rel, AccessShareLock);

	return gs_level_length;
}

static int4 get_domain_max_id()
{
	int4 gs_domain_max_id = -1;
	Relation rel = NULL;
	TableScanDesc scan = NULL;
	HeapTuple tuple = NULL;
	Form_abac_domain domain_sec_form = NULL;
	rel = heap_open(DomainSecRelationId, AccessShareLock);
	scan = heap_beginscan(rel, SnapshotNow, 0, NULL);

	while ((tuple = heap_getnext(scan, ForwardScanDirection)) != NULL)
	{
		domain_sec_form = (Form_abac_domain)GETSTRUCT(tuple);
		if (gs_domain_max_id < domain_sec_form->id)
			gs_domain_max_id = domain_sec_form->id;
	}
	heap_endscan(scan);
	heap_close(rel, AccessShareLock);

	return gs_domain_max_id;
}

static Oid get_level_oid(const char *name)
{
	Relation rel = NULL;
	TableScanDesc scan = NULL;
	HeapTuple tuple = NULL;
	Form_abac_level level_sec_form = NULL;
	rel = heap_open(LevelSecRelationId, AccessShareLock);
	scan = heap_beginscan(rel, SnapshotNow, 0, NULL);

	Oid result = 0;
	bool found = false;

	while ((tuple = heap_getnext(scan, ForwardScanDirection)) != NULL)
	{
		level_sec_form = (Form_abac_level)GETSTRUCT(tuple);
		if (!strcmp(NameStr(level_sec_form->name), name))
		{
			found = true;
			result = HeapTupleGetOid(tuple);
			break;
		}
	}

	heap_endscan(scan);
	heap_close(rel, AccessShareLock);

	if (!found)
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_OBJECT),
					errmsg("level %s does not exist", name)));
	
	return result;
}

static Oid get_domain_oid(const char *name)
{
	Relation rel = NULL;
	TableScanDesc scan = NULL;
	HeapTuple tuple = NULL;
	Form_abac_domain domain_sec_form = NULL;
	rel = heap_open(DomainSecRelationId, AccessShareLock);
	scan = heap_beginscan(rel, SnapshotNow, 0, NULL);

	Oid result = 0;
	bool found = false;

	while ((tuple = heap_getnext(scan, ForwardScanDirection)) != NULL)
	{
		domain_sec_form = (Form_abac_domain)GETSTRUCT(tuple);
		if (!strcmp(NameStr(domain_sec_form->name), name))
		{
			found = true;
			result = HeapTupleGetOid(tuple);
			break;
		}
	}

	heap_endscan(scan);
	heap_close(rel, AccessShareLock);

	if (!found)
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_OBJECT),
					errmsg("domain %s does not exist", name)));
	return result;
}

static bool check_role()
{
	Oid roleid = GetUserId();
	if (superuser_arg(roleid) || systemDBA_arg(roleid) || roleid == DEFAULT_ROLE_ABAC_MANAGER)
	{
		return true;
	}
	return false;
}

static bool check_abac()
{
	return u_sess->attr.attr_common.enable_abac;
}

static bool checkDependencyOnMyself(Oid classid, Oid objid)
{
	Relation depRel;
	SysScanDesc depScan;
	ScanKeyData key[2];
	HeapTuple depTup;
	bool found = false;

	depRel = heap_open(DependRelationId, AccessShareLock);

	ScanKeyInit(&key[0], Anum_pg_depend_refclassid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(classid));
	ScanKeyInit(&key[1], Anum_pg_depend_refobjid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(objid));

	depScan = systable_beginscan(depRel, DependReferenceIndexId, true, NULL, 2, key);

	while (HeapTupleIsValid(depTup = systable_getnext(depScan)))
	{
		Form_pg_depend depForm = (Form_pg_depend)GETSTRUCT(depTup);

		if (depForm->deptype == DEPENDENCY_NORMAL)
		{
			found = true;
			break;
		}
	}

	systable_endscan(depScan);
	heap_close(depRel, AccessShareLock);

	return found;
}

static void recordDependencyOnRef(Oid classid, Oid objid, Oid refclassid, Oid refobjid)
{
	ObjectAddress myself;
	ObjectAddress referenced;

	myself.classId = classid;
	myself.objectId = objid;
	myself.objectSubId = 0;

	referenced.classId = refclassid;
	referenced.objectId = refobjid;
	referenced.objectSubId = 0;

	recordDependencyOn(&myself, &referenced, DEPENDENCY_NORMAL);
}

bool abac_create_level(const char *name_old, const char *name_new)
{
	if (!check_abac())
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("abac has not been started")));

	if (!check_role())
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied for create level")));

	if (name_old == NULL || name_new == NULL || name_new[0] == '\0')
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("Invalid parameter")));

	int4 grade_old = 0, grade_new = 0;
	bool ret = false;
	ret = get_grade_by_name_from_level(name_new, NULL);
	if (ret == true)
		ereport(ERROR, (errmsg("level %s already exists", name_new)));

	int4 gs_level_length = get_level_length();
	if (name_old[0] == '\0')
	{
		if (gs_level_length != 0)
		{
			for (int4 i = gs_level_length - 1; i >= 0; --i)
				update_level_grade(i, i + 1);
		}
		grade_new = 0;
	}
	else
	{
		ret = get_grade_by_name_from_level(name_old, &grade_old);
		if (ret == false)
			ereport(ERROR, (errmsg("level %s does not exist", name_old)));

		for (int4 i = gs_level_length - 1; i > grade_old; --i)
		{
			update_level_grade(i, i + 1);
		}
		grade_new = grade_old + 1;
	}

	insert_level(grade_new, name_new);
	return true;
}

bool abac_drop_level(const char *name)
{
	if (!check_abac())
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("abac has not been started")));

	if (!check_role())
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied for drop level")));

	if (name == NULL || name[0] == '\0')
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("Invalid parameter")));
	
	bool dret = checkDependencyOnMyself(LevelSecRelationId, get_level_oid(name));
	if (dret)
		ereport(ERROR, (errmsg("cannot drop the object because other objects depend on it")));


	int4 grade = 0;
	bool ret = false;
	ret = get_grade_by_name_from_level(name, &grade);
	if (ret == false)
		ereport(ERROR, (errmsg("level %s does not exist", name)));
	delete_level(grade);
	int4 gs_level_length = get_level_length();
	for (int4 i = grade; i < gs_level_length - 1; ++i)
		update_level_grade(i + 1, i);
	return true;
}

bool abac_create_domain(const char *name_old, const char *name_new)
{
	if (!check_abac())
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("abac has not been started")));

	if (!check_role())
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied for create domain")));

	if (name_old == NULL || name_new == NULL || name_new[0] == '\0')
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("Invalid parameter")));

	int4 id_old = 0, id_new = 0;
	int4 rid_old = 0, rid_new = 0;
	bool ret = false;

	ret = get_domain_by_name(name_new, NULL, NULL);
	if (ret == true)
		ereport(ERROR, (errmsg("domain %s already exists", name_new)));
	if (name_old[0] == '\0')
		id_old = -1;
	else
	{
		ret = get_domain_by_name(name_old, &id_old, &rid_old);
		if (ret == false)
			ereport(ERROR, (errmsg("domain %s does not exist", name_old)));
	}
	id_new = get_domain_max_id() + 1;
	rid_new = id_old;
	insert_domain(id_new, name_new, rid_new);
	return true;
}

bool abac_drop_domain(const char *name)
{
	if (!check_abac())
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("abac has not been started")));

	if (!check_role())
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied for drop domain")));

	if (name == NULL || name[0] == '\0')
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("Invalid parameter")));

	bool dret = checkDependencyOnMyself(DomainSecRelationId, get_domain_oid(name));
	if (dret)
		ereport(ERROR, (errmsg("cannot drop the object because other objects depend on it")));

	int4 id = 0;
	bool ret = false;
	ret = get_domain_by_name(name, &id, NULL);
	if (ret == false)
		ereport(ERROR, (errmsg("domain %s does not exist", name)));
	if (domain_have_child(id))
		ereport(ERROR, (errmsg("cannot delete domain %s because it has child", name)));
	delete_domain(id);
	return true;
}

static bool check_obj_att_exists(const char *object, const char *object_type, const char *att_name)
{
	Relation rel = NULL;
	ScanKeyData skey[2];
	SysScanDesc scan = NULL;
	HeapTuple tuple = NULL;
	bool res = false;

	rel = heap_open(AttributesManagerRelationId, AccessShareLock);
	ScanKeyInit(&skey[0], Anum_abac_attributes_manager_object, BTEqualStrategyNumber, F_NAMEEQ, CStringGetDatum(object));
	ScanKeyInit(&skey[1], Anum_abac_attributes_manager_attribute_name, BTEqualStrategyNumber, F_NAMEEQ, CStringGetDatum(att_name));
	scan = systable_beginscan(rel, AbacAttributesManagerObjectNameValueIndexId, true, NULL, 2, skey);
	while (HeapTupleIsValid(tuple = systable_getnext(scan)))
	{
		Form_abac_attributes_manager form = (Form_abac_attributes_manager)GETSTRUCT(tuple);
		if (form->object_type == get_enumlabeloid(ABACATTMANAGEROBJECTTYPEOID, object_type))
		{
			res = true;
			break;
		}
	}

	systable_endscan(scan);
	heap_close(rel, AccessShareLock);
	return res;
}

static void recordPolicyDependcyOnAtt(Oid objid, const char *object, const char *object_type, const char *att_name)
{
	if (!strcmp(att_name, "domain"))
		return;

	Relation rel = NULL;
	ScanKeyData skey[2];
	SysScanDesc scan = NULL;
	HeapTuple tuple = NULL;

	rel = heap_open(AttributesManagerRelationId, AccessShareLock);
	ScanKeyInit(&skey[0], Anum_abac_attributes_manager_object, BTEqualStrategyNumber, F_NAMEEQ, CStringGetDatum(object));
	ScanKeyInit(&skey[1], Anum_abac_attributes_manager_attribute_name, BTEqualStrategyNumber, F_NAMEEQ, CStringGetDatum(att_name));
	scan = systable_beginscan(rel, AbacAttributesManagerObjectNameValueIndexId, true, NULL, 2, skey);
	while (HeapTupleIsValid(tuple = systable_getnext(scan)))
	{
		Form_abac_attributes_manager form = (Form_abac_attributes_manager)GETSTRUCT(tuple);
		if (form->object_type == get_enumlabeloid(ABACATTMANAGEROBJECTTYPEOID, object_type))
		{
			Oid refoid = HeapTupleGetOid(tuple);
			recordDependencyOnRef(PolicysRelationId, objid, AttributesManagerRelationId, refoid);
		}
	}

	systable_endscan(scan);
	heap_close(rel, AccessShareLock);
}

bool checkPolicyConflicts(const char *name,
						  const char *subject,
						  const char *object,
						  const abacPolicyObjectType &object_type,
						  const abacPolicyActionType &action,
						  const char *att_name,
						  const char *const_val,
						  const abacPolicyOperator &policy_operator,
						  const abacPolicyTag &tag)
{

	const char *ip = "";
	PPOLICY cur_list = (PPOLICY)palloc(sizeof(GaussPOLICY));
	strcpy(NameStr(cur_list[0].name), name);
	strcpy(NameStr(cur_list[0].subject), subject);
	strcpy(NameStr(cur_list[0].object), object);
	cur_list[0].object_type = object_type;
	cur_list[0].action = action;
	strcpy(NameStr(cur_list[0].att_name), att_name);
	strcpy(NameStr(cur_list[0].const_val), const_val);
	cur_list[0].policy_operator = policy_operator;
	cur_list[0].tag = tag;
	int cur_state = policyDecision(subject, ABAC_ATTMANAGER_OBJECT_TYPE_USER, object, (abacAttManagerObjectType)object_type, cur_list[0], ip);

	bool ret = false;

	PPOLICY list = NULL;
	size_t list_length = 0;
	search_policy(subject, object, (abacAttManagerObjectType)object_type, action, &list, list_length);
	int state = 0;
	for (size_t i = 0; i < list_length; ++i)
	{
		state = policyDecision(subject, ABAC_ATTMANAGER_OBJECT_TYPE_USER, object, (abacAttManagerObjectType)object_type, list[i], ip);
		if (cur_state != state)
		{
			ret = true;
			ereport(WARNING, (errmsg("policy \'%s\' conflicts with policy \'%s\'", NameStr(list[i].name), name)));
			break;
		}
	}
	pfree(cur_list);
	if (list != NULL)
		pfree(list);
	return ret;
}

bool abac_create_policy(const char *name,
						const char *subject,
						const char *object,
						const char *object_type,
						const char *action,
						const char *att_name,
						const char *const_val,
						const char *policy_operator,
						const char *tag,
						bool enable)
{
	if (!check_abac())
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("abac has not been started")));

	if (!check_role())
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied for create policy")));

	if (name == NULL || subject == NULL || object == NULL || object_type == NULL || action == NULL ||
		att_name == NULL || policy_operator == NULL || const_val == NULL || tag == NULL)
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("Invalid parameter")));
	
	if (!strcmp(tag, "ENVIRONMENT_VALUE") && 
		strcmp(att_name, "ip") && strcmp(att_name, "date") && strcmp(att_name, "time") && strcmp(att_name, "weekday"))
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("Invalid parameter")));
	
	Oid object_typoid = get_enumlabeloid(ABACPOLICYOBJECTTYPEOID, object_type);
	Oid actionoid = get_enumlabeloid(ABACPOLICYACTIONTYPEOID, action);
	Oid operatoroid = get_enumlabeloid(ABACPOLICYOPERATOROID, policy_operator);
	Oid tagoid = get_enumlabeloid(ABACPOLICYTAGOID, tag);

	if (strcmp(subject, "any") != 0 && strcmp(tag, "ENVIRONMENT_VALUE") != 0 && !check_obj_att_exists(subject, "USER", att_name))
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("%s(USER) does not have attribute %s", subject, att_name)));

	if (strcmp(object, "any") != 0 && strcmp(tag, "ATTRIBUTE_ATTRIBUTE") == 0 && !check_obj_att_exists(object, object_type, att_name))
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("%s(%s) does not have attribute %s", object, object_type, att_name)));

	if (!strcmp(tag, "ATTRIBUTE_VALUE"))
	{
		if (!strcmp(att_name, "level"))
			(void)get_level_oid(const_val);
		if (!strcmp(att_name, "domain"))
			(void)get_domain_oid(const_val);
	}

	if (enable && strcmp(name, "any") && strcmp(object, "any") && strcmp(object_type, "ANY") && strcmp(tag, "ENVIRONMENT_VALUE"))
		(void)checkPolicyConflicts(name, 
								   subject,
								   object,
								   get_policy_object_type(object_typoid),
								   get_policy_action_type(actionoid),
								   att_name,
								   const_val,
								   get_policy_operator(operatoroid),
								   get_policy_tag(tagoid));

	Datum values[Natts_abac_policies];
	bool nulls[Natts_abac_policies];
	Relation rel = NULL;
	HeapTuple tuple = NULL;

	errno_t errorno = EOK;
	errorno = memset_s(values, sizeof(values), 0, sizeof(values));
	securec_check_c(errorno, "\0", "\0");
	errorno = memset_s(nulls, sizeof(nulls), 0, sizeof(nulls));
	securec_check_c(errorno, "\0", "\0");

	NameData policy_name;
	NameData subject_name;
	NameData object_name;
	NameData att_name_name;
	NameData const_val_name;

	namestrcpy(&policy_name, name);
	namestrcpy(&subject_name, subject);
	namestrcpy(&object_name, object);
	namestrcpy(&att_name_name, att_name);
	namestrcpy(&const_val_name, const_val);

	values[Anum_abac_policies_name - 1] = NameGetDatum(&policy_name);
	values[Anum_abac_policies_subject - 1] = NameGetDatum(&subject_name);
	values[Anum_abac_policies_object - 1] = NameGetDatum(&object_name);
	values[Anum_abac_policies_object_type - 1] = ObjectIdGetDatum(object_typoid);
	values[Anum_abac_policies_action - 1] = ObjectIdGetDatum(actionoid);
	values[Anum_abac_policies_att_name - 1] = NameGetDatum(&att_name_name);
	values[Anum_abac_policies_const_val - 1] = NameGetDatum(&const_val_name);
	values[Anum_abac_policies_policy_operator - 1] = ObjectIdGetDatum(operatoroid);
	values[Anum_abac_policies_tag - 1] = ObjectIdGetDatum(tagoid);
	values[Anum_abac_policies_enable - 1] = BoolGetDatum(enable);

	rel = heap_open(PolicysRelationId, RowExclusiveLock);
	tuple = heap_form_tuple(RelationGetDescr(rel), values, nulls);

	simple_heap_insert(rel, tuple);
	CatalogUpdateIndexes(rel, tuple);

	Oid tuple_oid = HeapTupleGetOid(tuple);

	if (strcmp(subject, "any") != 0 && strcmp(tag, "ENVIRONMENT_VALUE") != 0)
		recordPolicyDependcyOnAtt(tuple_oid, subject, "USER", att_name);
	if (strcmp(object, "any") != 0 && strcmp(tag, "ATTRIBUTE_ATTRIBUTE") == 0)
		recordPolicyDependcyOnAtt(tuple_oid, object, object_type, att_name);
	if (!strcmp(tag, "ATTRIBUTE_VALUE"))
	{
		if (!strcmp(att_name, "level"))
		{
			Oid leveloid = get_level_oid(const_val);
			recordDependencyOnRef(PolicysRelationId, tuple_oid, LevelSecRelationId, leveloid);
		}
		if (!strcmp(att_name, "domain"))
		{
			Oid domainoid = get_domain_oid(const_val);
			recordDependencyOnRef(PolicysRelationId, tuple_oid, DomainSecRelationId, domainoid);
		}
	}

	heap_freetuple_ext(tuple);
	heap_close(rel, RowExclusiveLock);

	return true;
}

bool abac_drop_policy(const char *name)
{
	if (!check_abac())
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("abac has not been started")));

	if (!check_role())
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied for drop policy")));

	if (name == NULL)
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("Invalid parameter")));

	Relation rel = NULL;
	ScanKeyData skey[1];
	SysScanDesc scan = NULL;
	HeapTuple tuple = NULL;

	rel = heap_open(PolicysRelationId, RowExclusiveLock);
	ScanKeyInit(&skey[0], Anum_abac_policies_name, BTEqualStrategyNumber, F_NAMEEQ, CStringGetDatum(name));
	scan = systable_beginscan(rel, AbacPoliciesNameIndexId, true, NULL, 1, skey);
	tuple = systable_getnext(scan);
	if (HeapTupleIsValid(tuple))
	{
		Oid policy_mgr_oid = HeapTupleGetOid(tuple);
		simple_heap_delete(rel, &tuple->t_self);
		deleteDependencyRecordsFor(PolicysRelationId, policy_mgr_oid, false);
		CatalogUpdateIndexes(rel, tuple);
	}
	systable_endscan(scan);
	heap_close(rel, RowExclusiveLock);

	return true;
}

bool abac_alter_policy_on(const char *name)
{
	if (!check_abac())
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("abac has not been started")));

	if (!check_role())
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied for alter policy on")));

	if (name == NULL)
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("Invalid parameter")));

	Relation rel = NULL;
	ScanKeyData skey[1];
	SysScanDesc scan = NULL;
	HeapTuple tuple = NULL;

	rel = heap_open(PolicysRelationId, RowExclusiveLock);
	ScanKeyInit(&skey[0], Anum_abac_policies_name, BTEqualStrategyNumber, F_NAMEEQ, CStringGetDatum(name));
	scan = systable_beginscan(rel, AbacPoliciesNameIndexId, true, NULL, 1, skey);
	tuple = systable_getnext(scan);

	if (HeapTupleIsValid(tuple))
	{
		bool nulls[Natts_abac_policies];
		Datum values[Natts_abac_policies];
		bool replaces[Natts_abac_policies];

		errno_t errorno = EOK;
		errorno = memset_s(nulls, sizeof(nulls), 0, sizeof(nulls));
		securec_check_c(errorno, "\0", "\0");
		errorno = memset_s(values, sizeof(values), 0, sizeof(values));
		securec_check_c(errorno, "\0", "\0");
		errorno = memset_s(replaces, sizeof(replaces), 0, sizeof(replaces));
		securec_check_c(errorno, "\0", "\0");

		values[Anum_abac_policies_enable - 1] = BoolGetDatum(true);
		replaces[Anum_abac_policies_enable - 1] = true;

		tuple = heap_modify_tuple(tuple, RelationGetDescr(rel), values, nulls, replaces);
		simple_heap_update(rel, &tuple->t_self, tuple);
		CatalogUpdateIndexes(rel, tuple);
	}

	systable_endscan(scan);
	heap_close(rel, RowExclusiveLock);

	return true;
}

bool abac_alter_policy_off(const char *name)
{
	if (!check_abac())
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("abac has not been started")));

	if (!check_role())
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied for alter policy off")));

	if (name == NULL)
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("Invalid parameter")));

	Relation rel = NULL;
	ScanKeyData skey[1];
	SysScanDesc scan = NULL;
	HeapTuple tuple = NULL;

	rel = heap_open(PolicysRelationId, RowExclusiveLock);
	ScanKeyInit(&skey[0], Anum_abac_policies_name, BTEqualStrategyNumber, F_NAMEEQ, CStringGetDatum(name));

	scan = systable_beginscan(rel, AbacPoliciesNameIndexId, true, NULL, 1, skey);
	tuple = systable_getnext(scan);

	if (HeapTupleIsValid(tuple))
	{
		bool nulls[Natts_abac_policies];
		Datum values[Natts_abac_policies];
		bool replaces[Natts_abac_policies];

		errno_t errorno = EOK;
		errorno = memset_s(nulls, sizeof(nulls), 0, sizeof(nulls));
		securec_check_c(errorno, "\0", "\0");
		errorno = memset_s(values, sizeof(values), 0, sizeof(values));
		securec_check_c(errorno, "\0", "\0");
		errorno = memset_s(replaces, sizeof(replaces), 0, sizeof(replaces));
		securec_check_c(errorno, "\0", "\0");

		values[Anum_abac_policies_enable - 1] = BoolGetDatum(false);
		replaces[Anum_abac_policies_enable - 1] = true;

		tuple = heap_modify_tuple(tuple, RelationGetDescr(rel), values, nulls, replaces);
		simple_heap_update(rel, &tuple->t_self, tuple);
		CatalogUpdateIndexes(rel, tuple);
	}

	systable_endscan(scan);
	heap_close(rel, RowExclusiveLock);

	return true;
}

bool abac_create_attribute(const char *name, const char *type)
{
	if (!check_abac())
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("abac has not been started")));

	if (!check_role())
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied for create attribute")));

	if (name == NULL || type == NULL)
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("Invalid parameter")));

	Oid att_typoid = get_enumlabeloid(ABACATTTYPEOID, type);

	Datum values[Natts_abac_attributes];
	bool nulls[Natts_abac_attributes];
	Relation rel = NULL;
	HeapTuple tuple = NULL;

	NameData attribute_name, attribute_type;

	errno_t errorno = EOK;

	errorno = memset_s(values, sizeof(values), 0, sizeof(values));
	securec_check_c(errorno, "\0", "\0");

	errorno = memset_s(nulls, sizeof(nulls), 0, sizeof(nulls));
	securec_check_c(errorno, "\0", "\0");

	namestrcpy(&attribute_name, name);
	namestrcpy(&attribute_type, type);

	values[Anum_abac_attributes_name - 1] = NameGetDatum(&attribute_name);
	values[Anum_abac_attributes_type - 1] = ObjectIdGetDatum(att_typoid);

	rel = heap_open(AttributesRelationId, RowExclusiveLock);
	tuple = heap_form_tuple(RelationGetDescr(rel), values, nulls);

	(void)simple_heap_insert(rel, tuple);
	CatalogUpdateIndexes(rel, tuple);

	heap_freetuple_ext(tuple);
	heap_close(rel, RowExclusiveLock);

	return true;
}

bool abac_drop_attribute(const char *name)
{
	if (!check_abac())
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("abac has not been started")));

	if (!check_role())
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied for delete attribute")));

	if (name == NULL)
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("Invalid parameter")));

	if (!strcmp(name, "level") || !strcmp(name, "domain") || !strcmp(name, "ip") || !strcmp(name, "date") || !strcmp(name, "time") || !strcmp(name, "weekday"))
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("default attribute '%s' cannot be dropped", name)));

	Relation rel = NULL;
	ScanKeyData skey[1];
	SysScanDesc scan = NULL;
	HeapTuple tuple = NULL;

	rel = heap_open(AttributesRelationId, RowExclusiveLock);
	ScanKeyInit(&skey[0], Anum_abac_attributes_name, BTEqualStrategyNumber, F_NAMEEQ, CStringGetDatum(name));
	scan = systable_beginscan(rel, AbacAttributesNameIndexId, true, NULL, 1, skey);
	tuple = systable_getnext(scan);
	bool dret = false;
	if (HeapTupleIsValid(tuple))
	{
		Oid att_oid = HeapTupleGetOid(tuple);
		dret = checkDependencyOnMyself(AttributesRelationId, att_oid);
		if (!dret)
			simple_heap_delete(rel, &tuple->t_self);
	}
	systable_endscan(scan);
	heap_close(rel, RowExclusiveLock);

	if (dret)
		ereport(ERROR, (errmsg("cannot drop the object because other objects depend on it")));

	return true;
}

static bool check_int_is_valid(const char *value)
{
	if (value == NULL)
		return false;
	char *pEnd = NULL;
	long num = strtol(value, &pEnd, 10);
	if (pEnd == NULL || *pEnd != '\0')
		return false;
	return INT_MIN <= num && num <= INT_MAX;
}

static bool check_double_is_valid(const char *value)
{
	if (value == NULL)
		return false;
	char *pEnd = NULL;
	strtod(value, &pEnd);
	return pEnd != NULL && *pEnd == '\0';
}

static bool check_bool_is_valid(const char *value)
{
	if (value == NULL)
		return false;
	return !strcmp(value, "true") || !strcmp(value, "false") || !strcmp(value, "1") || !strcmp(value, "0");
}

static bool check_ip_is_valid(const char *ip)
{
	if (ip == NULL)
		return false;
	if (!strcmp(ip, "localhost"))
		return true;
	size_t len = strlen(ip);
	if (len < 7 || len > 15)
		return false;
	int dot_count = 0, num = 0;
	for (size_t i = 0; i < len; ++i)
	{
		if (ip[i] == '.')
		{
			++dot_count;
			if (num > 255)
				return false;
			num = 0;
		}
		else if (isdigit(ip[i]))
			num = num * 10 + ip[i] - '0';
		else
			return false;
	}
	return dot_count == 3 && num <= 255;
}

static bool check_date_is_valid(const char *date)
{
	if (date == NULL || strlen(date) != 10 || date[4] != '-' || date[7] != '-' || strcmp(date, "1970-01-01") == -1)
		return false;
	int year = 0, month = 0, day = 0;
	for (int i = 0; i < 4; ++i)
	{
		if (!isdigit(date[i]))
			return false;
		year = year * 10 + date[i] - '0';
	}
	for (int i = 5, j = 8; i < 7; ++i, ++j)
	{
		if (!isdigit(date[i]) || !isdigit(date[j]))
			return false;
		month = month * 10 + date[i] - '0';
		day = day * 10 + date[j] - '0';
	}
	if (month == 0 || month > 12 || day == 0)
		return false;
	if (month == 2)
		return day <= 28 + (year % 400 == 0 || (year % 4 == 0 && year % 100 != 0));
	return day <= 30 + (month == 1 || month == 3 || month == 5 || month == 7 || month == 8 || month == 10 || month == 12);
}

static bool check_datetime_is_valid(const char *datetime)
{
	if (datetime == NULL || strlen(datetime) != 8 || datetime[2] != ':' || datetime[5] != ':')
		return false;
	int hour = 0, minute = 0, second = 0;
	for (int i = 0, j = 3, k = 6; i < 2; ++i, ++j, ++k)
	{
		if (!isdigit(datetime[i]) || !isdigit(datetime[j]) || !isdigit(datetime[k]))
			return false;
		hour = hour * 10 + datetime[i] - '0';
		minute = minute * 10 + datetime[j] - '0';
		second = second * 10 + datetime[k] - '0';
	}
	return hour >= 0 && hour < 24 && minute >= 0 && minute < 60 && second >= 0 && second < 60;
}

static bool check_weekday_is_valid(const char *weekday)
{
	if (weekday == NULL || strlen(weekday) != 1)
		return false;
	return '1' <= weekday[0] && weekday[0] <= '7';
}

static bool check_attribute_is_valid(const char *name, const char *value)
{
	if (name == NULL || value == NULL)
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("invalid parameter")));

	if (strcmp(name, "level") == 0)
	{
		(void)get_level_oid(value);
		return true;
	}

	if (strcmp(name, "domain") == 0)
	{
		(void)get_domain_oid(value);
		return true;
	}

	if (!strcmp(name, "ip"))
	{
		if (!check_ip_is_valid(value))
			ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("invalid ip address format")));
		return true;
	}

	if (!strcmp(name, "weekday"))
	{
		if (!check_weekday_is_valid(value))
			ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("invalid weekday format")));
		return true;
	}

	abacAttType type = get_type_by_name_from_att(name);

	switch (type)
	{
	case ABAC_ATT_STRING:
		break;
	case ABAC_ATT_INT:
		if (!check_int_is_valid(value))
			ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("invalid int format")));
		break;
	case ABAC_ATT_DOUBLE:
		if (!check_double_is_valid(value))
			ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("invalid double format")));
		break;
	case ABAC_ATT_BOOL:
		if (!check_bool_is_valid(value))
			ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("invalid bool format")));
		break;
	case ABAC_ATT_DATE:
		if (!check_date_is_valid(value))
			ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("invalid date format")));
		break;
	case ABAC_ATT_DATETIME:
		if (!check_datetime_is_valid(value))
			ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("invalid datetime format")));
		break;
	default:
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("invalid type")));
		break;
	}
	return true;
}

Oid get_attribute_oid(const char *name)
{
	Oid result;
	HeapTuple tup;
	tup = SearchSysCache1(ABACATTRIBUTESNAME, CStringGetDatum(name));
	if (!HeapTupleIsValid(tup))
	{
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_OBJECT),
				 errmsg("attribute %s does not exist", name)));
	}
	result = HeapTupleGetOid(tup);
	ReleaseSysCache(tup);
	return result;
}

bool abac_grant_attribute(const char *name, const char *value, const char *object, const char *object_type)
{
	if (!check_abac())
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("abac has not been started")));

	if (!check_role())
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied for grant attribute")));

	if (!check_attribute_is_valid(name, value))
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("Invalid parameter")));

	Oid att_oid = get_attribute_oid(name);

	if (object == NULL || object_type == NULL)
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("Invalid parameter")));

	Oid object_typoid = get_enumlabeloid(ABACATTMANAGEROBJECTTYPEOID, object_type);

	Datum values[Natts_abac_attributes_manager];
	bool nulls[Natts_abac_attributes_manager];
	Relation rel = NULL;

	HeapTuple tuple = NULL;

	NameData attribute_object, attribute_name, attribute_value;

	errno_t errorno = EOK;

	errorno = memset_s(values, sizeof(values), 0, sizeof(values));
	securec_check_c(errorno, "\0", "\0");

	errorno = memset_s(nulls, sizeof(nulls), 0, sizeof(nulls));
	securec_check_c(errorno, "\0", "\0");

	namestrcpy(&attribute_object, object);
	namestrcpy(&attribute_name, name);
	namestrcpy(&attribute_value, value);

	values[Anum_abac_attributes_manager_object - 1] = NameGetDatum(&attribute_object);
	values[Anum_abac_attributes_manager_object_type - 1] = ObjectIdGetDatum(object_typoid);
	values[Anum_abac_attributes_manager_attribute_name - 1] = NameGetDatum(&attribute_name);
	values[Anum_abac_attributes_manager_attribute_value - 1] = NameGetDatum(&attribute_value);

	rel = heap_open(AttributesManagerRelationId, RowExclusiveLock);
	tuple = heap_form_tuple(RelationGetDescr(rel), values, nulls);
	(void)simple_heap_insert(rel, tuple);
	CatalogUpdateIndexes(rel, tuple);


	Oid tuple_oid = HeapTupleGetOid(tuple);
	recordDependencyOnRef(AttributesManagerRelationId, tuple_oid, AttributesRelationId, att_oid);

	if (strcmp(name, "level") == 0)
	{
		Oid level_oid = get_level_oid(value);
		recordDependencyOnRef(AttributesManagerRelationId, tuple_oid, LevelSecRelationId, level_oid);
	}
	if (strcmp(name, "domain") == 0)
	{
		Oid domain_oid = get_domain_oid(value);
		recordDependencyOnRef(AttributesManagerRelationId, tuple_oid, DomainSecRelationId, domain_oid);
	}


	heap_freetuple_ext(tuple);
	heap_close(rel, RowExclusiveLock);

	return true;
}

bool abac_revoke_attribute(const char *name, const char *value, const char *object, const char *object_type)
{
	if (!check_abac())
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("abac has not been started")));

	if (!check_role())
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied for revoke attribute")));

	if (!check_attribute_is_valid(name, value))
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("Invalid parameter")));

	if (object == NULL || object_type == NULL)
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("Invalid parameter")));

	Oid object_typoid = get_enumlabeloid(ABACATTMANAGEROBJECTTYPEOID, object_type);

	Relation rel = NULL;
	ScanKeyData skey[3];
	SysScanDesc scan = NULL;
	HeapTuple tuple = NULL;

	rel = heap_open(AttributesManagerRelationId, RowExclusiveLock);
	ScanKeyInit(&skey[0], Anum_abac_attributes_manager_object, BTEqualStrategyNumber, F_NAMEEQ, CStringGetDatum(object));
	ScanKeyInit(&skey[1], Anum_abac_attributes_manager_attribute_name, BTEqualStrategyNumber, F_NAMEEQ, CStringGetDatum(name));
	ScanKeyInit(&skey[2], Anum_abac_attributes_manager_attribute_value, BTEqualStrategyNumber, F_NAMEEQ, CStringGetDatum(value));
	scan = systable_beginscan(rel, AbacAttributesManagerObjectNameValueIndexId, true, NULL, 3, skey);
	bool dret = false;
	while (HeapTupleIsValid(tuple = systable_getnext(scan)))
	{
		Form_abac_attributes_manager form = (Form_abac_attributes_manager)GETSTRUCT(tuple);
		if (form->object_type == object_typoid)
		{
			Oid att_mgr_oid = HeapTupleGetOid(tuple);
			dret = checkDependencyOnMyself(AttributesManagerRelationId, att_mgr_oid);
			if (!dret)
			{
				simple_heap_delete(rel, &tuple->t_self);
				deleteDependencyRecordsFor(AttributesManagerRelationId, att_mgr_oid, false);
			}
		}
	}
	systable_endscan(scan);
	heap_close(rel, RowExclusiveLock);

	if (dret)
		ereport(ERROR, (errmsg("cannot drop the object because other objects depend on it")));

	return true;
}

static char *get_user_ip()
{
	return u_sess->statement_cxt.client_addr;
}

bool check_database_sign(Oid db_oid, Oid roleid, AclMode mode)
{
	if (check_abac() == false)
	{
		return true;
	}

	char *user_name = GetUserNameById(roleid);
	char *db_name = get_database_name(db_oid);
	if (user_name == NULL || db_name == NULL)
	{
		if (user_name != NULL)
			pfree(user_name);
		if (db_name != NULL)
			pfree(db_name);
		ereport(ERROR, (errmsg("memory allocation failed")));
	}
	char *ip = NULL;
	if (get_user_ip() != NULL)
	{
		size_t len = strlen(get_user_ip());
		ip = (char *)palloc(len + 1);
		if (ip == NULL)
		{
			pfree(user_name);
			pfree(db_name);
			ereport(ERROR, (errmsg("memory allocation failed")));
		}
		memcpy(ip, get_user_ip(), len + 1);
	}
	else
	{
		ip = (char *)palloc(strlen("localhost") + 1);
		if (ip == NULL)
		{
			pfree(user_name);
			pfree(db_name);
			ereport(ERROR, (errmsg("memory allocation failed")));
		}
		strcpy(ip, "localhost");
	}

	abacPolicyActionType action = get_action(mode);

	PPOLICY list = NULL;
	size_t list_length = 0;
	search_policy(user_name, db_name, ABAC_ATTMANAGER_OBJECT_TYPE_DATABASE, action, &list, list_length);
	int state = 0;

	for (size_t i = 0; i < list_length; i++)
	{
		state = policyDecision(user_name, ABAC_ATTMANAGER_OBJECT_TYPE_USER, db_name, ABAC_ATTMANAGER_OBJECT_TYPE_DATABASE, list[i], ip);
		if (state == 0)
		{
			pfree(user_name);
			pfree(ip);
			ereport(ERROR, (errmodule(MOD_SEC), errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
							errmsg("permission denied for database \"%s\"", db_name),
							errdetail("Insufficient privileges for the policy: \"%s\"", NameStr(list[i].name))));
		}
	}
	pfree(user_name);
	pfree(db_name);
	pfree(ip);
	if (list != NULL)
		pfree(list);
	return list_length > 0;
}

bool check_namespace_sign(Oid namespace_oid, Oid roleid, AclMode mode)
{
	if (check_abac() == false)
	{
		return true;
	}

	char *user_name = GetUserNameById(roleid);
	char *schema_name = get_namespace_name(namespace_oid);
	if (user_name == NULL || schema_name == NULL)
	{
		if (user_name != NULL)
			pfree(user_name);
		if (schema_name != NULL)
			pfree(schema_name);
		ereport(ERROR, (errmsg("memory allocation failed")));
	}

	char *ip = NULL;
	if (get_user_ip() != NULL)
	{
		size_t len = strlen(get_user_ip());
		ip = (char *)palloc(len + 1);
		if (ip == NULL)
		{
			pfree(user_name);
			pfree(schema_name);
			ereport(ERROR, (errmsg("memory allocation failed")));
		}
		memcpy(ip, get_user_ip(), len + 1);
	}
	else
	{
		ip = (char *)palloc(strlen("localhost") + 1);
		if (ip == NULL)
		{
			pfree(user_name);
			pfree(schema_name);
			ereport(ERROR, (errmsg("memory allocation failed")));
		}
		strcpy(ip, "localhost");
	}
	abacPolicyActionType action = get_action(mode);

	PPOLICY list = NULL;
	size_t list_length = 0;
	search_policy(user_name, schema_name, ABAC_ATTMANAGER_OBJECT_TYPE_SCHEMA, action, &list, list_length);
	int state = 0;

	for (size_t i = 0; i < list_length; i++)
	{
		state = policyDecision(user_name, ABAC_ATTMANAGER_OBJECT_TYPE_USER, schema_name, ABAC_ATTMANAGER_OBJECT_TYPE_SCHEMA, list[i], ip);
		if (state == 0)
		{
			pfree(user_name);
			pfree(ip);
			ereport(ERROR, (errmodule(MOD_SEC), errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
							errmsg("permission denied for schema \"%s\"", schema_name),
							errdetail("Insufficient privileges for the policy: \"%s\"", NameStr(list[i].name))));
		}
	}
	pfree(user_name);
	pfree(schema_name);
	pfree(ip);
	if (list != NULL)
		pfree(list);
	return list_length > 0;
}

bool check_table_sign(Oid table_oid, Oid roleid, AclMode mode)
{
	if (check_abac() == false)
	{
		return true;
	}

	char *user_name = GetUserNameById(roleid);
	char *schema_name = get_namespace_name(get_rel_namespace(table_oid));
	char *table_name = get_rel_name(table_oid);
	if (user_name == NULL || schema_name == NULL || table_name == NULL)
	{
		if (user_name != NULL)
			pfree(user_name);
		if (schema_name != NULL)
			pfree(schema_name);
		if (table_name != NULL)
			pfree(table_name);
		ereport(ERROR, (errmsg("memory allocation failed")));
	}

	char *ip = NULL;
	if (get_user_ip() != NULL)
	{
		size_t len = strlen(get_user_ip());
		ip = (char *)palloc(len + 1);
		if (ip == NULL)
		{
			pfree(user_name);
			pfree(schema_name);
			pfree(table_name);
			ereport(ERROR, (errmsg("memory allocation failed")));
		}
		memcpy(ip, get_user_ip(), len + 1);
	}
	else
	{
		ip = (char *)palloc(strlen("localhost") + 1);
		if (ip == NULL)
		{
			pfree(user_name);
			pfree(schema_name);
			pfree(table_name);
			ereport(ERROR, (errmsg("memory allocation failed")));
		}
		strcpy(ip, "localhost");
	}

	char *obj_name = (char *)palloc(strlen(schema_name) + strlen(".") + strlen(table_name) + 1);
	if (obj_name == NULL)
	{
		pfree(user_name);
		pfree(schema_name);
		pfree(table_name);
		pfree(ip);
		ereport(ERROR, (errmsg("memory allocation failed")));
	}
	sprintf(obj_name, "%s.%s", schema_name, table_name);
	abacPolicyActionType action = get_action(mode);

	PPOLICY list = NULL;
	size_t list_length = 0;
	search_policy(user_name, obj_name, ABAC_ATTMANAGER_OBJECT_TYPE_TABLE, action, &list, list_length);
	int state = 0;

	for (size_t i = 0; i < list_length; i++)
	{
		state = policyDecision(user_name, ABAC_ATTMANAGER_OBJECT_TYPE_USER, obj_name, ABAC_ATTMANAGER_OBJECT_TYPE_TABLE, list[i], ip);
		if (state == 0)
		{
			pfree(user_name);
			pfree(schema_name);
			pfree(ip);
			pfree(obj_name);
			ereport(ERROR, (errmodule(MOD_SEC), errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
							errmsg("permission denied for relation \"%s\"", table_name),
							errdetail("Insufficient privileges for the policy: \"%s\"", NameStr(list[i].name))));
		}
	}

	pfree(user_name);
	pfree(schema_name);
	pfree(table_name);
	pfree(ip);
	pfree(obj_name);
	if (list != NULL)
		pfree(list);
	return list_length > 0;
}

bool check_attribute_sign(Oid table_oid, AttrNumber attnum, Oid roleid, AclMode mode)
{
	if (check_abac() == false)
	{
		return true;
	}

	char *user_name = GetUserNameById(roleid);
	char *schema_name = get_namespace_name(get_rel_namespace(table_oid));
	char *table_name = get_rel_name(table_oid);
	char *attr_name = get_attname(table_oid, attnum);
	if (user_name == NULL || schema_name == NULL || table_name == NULL || attr_name == NULL)
	{
		if (user_name == NULL)
			pfree(user_name);
		if (schema_name == NULL)
			pfree(schema_name);
		if (table_name == NULL)
			pfree(table_name);
		if (attr_name == NULL)
			pfree(attr_name);
		ereport(ERROR, (errmsg("memory allocation failed")));
	}

	char *ip = NULL;
	if (get_user_ip() != NULL)
	{
		size_t len = strlen(get_user_ip());
		ip = (char *)palloc(len + 1);
		if (ip == NULL)
		{
			pfree(user_name);
			pfree(schema_name);
			pfree(table_name);
			pfree(attr_name);
			ereport(ERROR, (errmsg("memory allocation failed")));
		}
		memcpy(ip, get_user_ip(), len + 1);
	}
	else
	{
		ip = (char *)palloc(strlen("localhost") + 1);
		if (ip == NULL)
		{
			pfree(user_name);
			pfree(schema_name);
			pfree(table_name);
			pfree(attr_name);
			ereport(ERROR, (errmsg("memory allocation failed")));
		}
		strcpy(ip, "localhost");
	}

	char *obj_name = (char *)palloc(strlen(schema_name) + strlen(".") + strlen(table_name) + strlen(".") + strlen(attr_name) + 1);
	if (obj_name == NULL)
	{
		pfree(user_name);
		pfree(schema_name);
		pfree(table_name);
		pfree(attr_name);
		pfree(ip);
		ereport(ERROR, (errmsg("memory allocation failed")));
	}
	sprintf(obj_name, "%s.%s.%s", schema_name, table_name, attr_name);
	abacPolicyActionType action = get_action(mode);

	PPOLICY list = NULL;
	size_t list_length = 0;
	search_policy(user_name, obj_name, ABAC_ATTMANAGER_OBJECT_TYPE_COLUMN, action, &list, list_length);
	int state = 0;

	for (size_t i = 0; i < list_length; i++)
	{
		state = policyDecision(user_name, ABAC_ATTMANAGER_OBJECT_TYPE_USER, obj_name, ABAC_ATTMANAGER_OBJECT_TYPE_COLUMN, list[i], ip);
		if (state == 0)
		{
			pfree(user_name);
			pfree(schema_name);
			pfree(ip);
			pfree(obj_name);
			ereport(ERROR, (errmodule(MOD_SEC), errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
							errmsg("permission denied for column \"%s\" of relation \"%s\"", attr_name, table_name),
							errdetail("Insufficient privileges for the policy: \"%s\"", NameStr(list[i].name))));
		}
	}

	pfree(user_name);
	pfree(schema_name);
	pfree(table_name);
	pfree(attr_name);
	pfree(ip);
	pfree(obj_name);
	if (list != NULL)
		pfree(list);
	return list_length > 0;
}
