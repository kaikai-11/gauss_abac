#include "parser/abac_policy.h"

static abacAttManagerObjectType get_attmanager_object_type(Oid object_type_oid)
{
	abacAttManagerObjectType ret;
	char *object_type_str = get_enumlabelname(object_type_oid);
	if (!strcmp(object_type_str, "DATABASE"))
		ret = ABAC_ATTMANAGER_OBJECT_TYPE_DATABASE;
	if (!strcmp(object_type_str, "SCHEMA"))
		ret = ABAC_ATTMANAGER_OBJECT_TYPE_SCHEMA;
	if (!strcmp(object_type_str, "TABLE"))
		ret = ABAC_ATTMANAGER_OBJECT_TYPE_TABLE;
	if (!strcmp(object_type_str, "COLUMN"))
		ret = ABAC_ATTMANAGER_OBJECT_TYPE_COLUMN;
	if (!strcmp(object_type_str, "USER"))
		ret = ABAC_ATTMANAGER_OBJECT_TYPE_USER;
	pfree(object_type_str);
	return ret;
}

static abacAttType get_att_type(Oid att_type_oid)
{
    abacAttType ret;
	char *att_type_str = get_enumlabelname(att_type_oid);
    if (!strcmp(att_type_str, "INT"))
        ret = ABAC_ATT_INT;
    if (!strcmp(att_type_str, "DOUBLE"))
        ret = ABAC_ATT_DOUBLE;
    if (!strcmp(att_type_str, "STRING"))
        ret = ABAC_ATT_STRING;
    if (!strcmp(att_type_str, "DATE"))
        ret = ABAC_ATT_DATE;
    if (!strcmp(att_type_str, "DATETIME"))
        ret = ABAC_ATT_DATETIME;
    if (!strcmp(att_type_str, "SET"))
        ret = ABAC_ATT_SET;
    if (!strcmp(att_type_str, "BOOL"))
        ret = ABAC_ATT_BOOL;
    pfree(att_type_str);
    return ret;
}

abacPolicyObjectType get_policy_object_type(Oid object_type_oid)
{
	abacPolicyObjectType ret;
	char *object_type_str = get_enumlabelname(object_type_oid);
	if (!strcmp(object_type_str, "ANY"))
		ret = ABAC_POLICY_OBJECT_TYPE_ANY;
	if (!strcmp(object_type_str, "DATABASE"))
		ret = ABAC_POLICY_OBJECT_TYPE_DATABASE;
	if (!strcmp(object_type_str, "SCHEMA"))
		ret = ABAC_POLICY_OBJECT_TYPE_SCHEMA;
	if (!strcmp(object_type_str, "TABLE"))
		ret = ABAC_POLICY_OBJECT_TYPE_TABLE;
	if (!strcmp(object_type_str, "COLUMN"))
		ret = ABAC_POLICY_OBJECT_TYPE_COLUMN;
	pfree(object_type_str);
	return ret;
}

abacPolicyActionType get_policy_action_type(Oid action_type_oid)
{
	abacPolicyActionType ret;
	char *action_type_str = get_enumlabelname(action_type_oid);
	if (!strcmp(action_type_str, "ANY"))
		ret = ABAC_POLICY_ACTION_TYPE_ANY;
	if (!strcmp(action_type_str, "SELECT"))
		ret = ABAC_POLICY_ACTION_TYPE_SELECT;
	if (!strcmp(action_type_str, "INSERT"))
		ret = ABAC_POLICY_ACTION_TYPE_INSERT;
	if (!strcmp(action_type_str, "UPDATE"))
		ret = ABAC_POLICY_ACTION_TYPE_UPDATE;
	if (!strcmp(action_type_str, "DELETE"))
		ret = ABAC_POLICY_ACTION_TYPE_DELETE;
	return ret;
}

abacPolicyOperator get_policy_operator(Oid operator_oid)
{
	abacPolicyOperator ret;
	char *operator_str = get_enumlabelname(operator_oid);
	if (!strcmp(operator_str, "CONTAIN"))
		ret = ABAC_POLICY_OPERATOR_CONTAIN;
    if (!strcmp(operator_str, "NOT_CONTAIN"))
		ret = ABAC_POLICY_OPERATOR_NOT_CONTAIN;
	if (!strcmp(operator_str, "EQ"))
		ret = ABAC_POLICY_OPERATOR_EQ;
    if (!strcmp(operator_str, "LT"))
		ret = ABAC_POLICY_OPERATOR_LT;
	if (!strcmp(operator_str, "NE"))
		ret = ABAC_POLICY_OPERATOR_NE;
    if (!strcmp(operator_str, "LE"))
		ret = ABAC_POLICY_OPERATOR_LE;
	if (!strcmp(operator_str, "GT"))
		ret = ABAC_POLICY_OPERATOR_GT;
    if (!strcmp(operator_str, "GE"))
		ret = ABAC_POLICY_OPERATOR_GE;
    if (!strcmp(operator_str, "LIKE"))
		ret = ABAC_POLICY_OPERATOR_LIKE;
	pfree(operator_str);
	return ret;
}

abacPolicyTag get_policy_tag(Oid tag_oid)
{
	abacPolicyTag ret;
	char *tag_str = get_enumlabelname(tag_oid);
	if (!strcmp(tag_str, "ATTRIBUTE_ATTRIBUTE"))
		ret = ABAC_POLICY_TAG_ATTRIBUTE_ATTRIBUTE;
	if (!strcmp(tag_str, "ATTRIBUTE_VALUE"))
		ret = ABAC_POLICY_TAG_ATTRIBUTE_VALUE;
	if (!strcmp(tag_str, "ENVIRONMENT_VALUE"))
		ret = ABAC_POLICY_TAG_ENVIRONMENT_VALUE;
	pfree(tag_str);
	return ret;
}

static bool object_match(const char *object, const char *form_object, const abacAttManagerObjectType &object_type)
{
    if (object == NULL || object[0] == '\0' ||
        form_object == NULL || form_object[0] == '\0')
        return false;

    if (!strcmp(object, form_object))
        return true;
    size_t object_length = strlen(object);
    size_t form_object_length = strlen(form_object);
    if (!(object_type == ABAC_ATTMANAGER_OBJECT_TYPE_SCHEMA ||
          object_type == ABAC_ATTMANAGER_OBJECT_TYPE_TABLE ||
          object_type == ABAC_ATTMANAGER_OBJECT_TYPE_COLUMN) ||
        form_object[form_object_length - 1] != '*')
        return false;
    if (object_length < form_object_length)
        return false;
    int dot_count = 0;
    for (size_t i = 0; i < form_object_length - 1; ++i)
        if (object[i] != form_object[i])
            return false;
        else if (form_object[i] == '.')
            ++dot_count;
    if (object_type == ABAC_ATTMANAGER_OBJECT_TYPE_SCHEMA)
        return dot_count == 0;
    else if (object_type == ABAC_ATTMANAGER_OBJECT_TYPE_TABLE)
        return dot_count == 1;
    else
        return dot_count == 2;
}

bool search_policy(const char *subject,
                   const char *object,
                   const abacAttManagerObjectType &object_type,
                   const abacPolicyActionType &action,
                   PPOLICY *list,
                   size_t &list_length)
{
    list_length = 0;
    if (subject == NULL || object == NULL)
        return false;

    if (*list != NULL)
        pfree(*list);
    *list = (PPOLICY)palloc(sizeof(GaussPOLICY));
    if (*list == NULL)
        ereport(ERROR, (errmsg("memory allocation failed")));

    size_t list_allocated_length = 1;

    Relation rel = NULL;
    TableScanDesc scan = NULL;
    HeapTuple tuple = NULL;
    Form_abac_policies policies_form = NULL;
    rel = heap_open(PolicysRelationId, AccessShareLock);
    scan = heap_beginscan(rel, SnapshotNow, 0, NULL);

    while ((tuple = heap_getnext(scan, ForwardScanDirection)) != NULL)
    {
        policies_form = (Form_abac_policies)GETSTRUCT(tuple);
        if (policies_form->enable &&
            (!strcmp(NameStr(policies_form->subject), subject) ||
             !strcmp(NameStr(policies_form->subject), "any")) &&
            ((int)get_policy_object_type(policies_form->object_type) == (int)object_type ||
             get_policy_object_type(policies_form->object_type) == ABAC_POLICY_OBJECT_TYPE_ANY) &&
            (object_match(object, NameStr(policies_form->object), object_type) ||
             !strcmp(NameStr(policies_form->object), "any")) &&
            ((get_policy_action_type(policies_form->action) & action) || get_policy_action_type(policies_form->action) == ABAC_POLICY_ACTION_TYPE_ANY))
        {
            if (list_length == list_allocated_length)
            {
                list_allocated_length *= 2;
                *list = (PPOLICY)repalloc(*list, list_allocated_length * sizeof(GaussPOLICY));
                if (*list == NULL)
                    ereport(ERROR, (errmsg("memory allocation failed")));
            }
            strcpy(NameStr((*list)[list_length].name), NameStr(policies_form->name));
            strcpy(NameStr((*list)[list_length].subject), NameStr(policies_form->subject));
            strcpy(NameStr((*list)[list_length].object), NameStr(policies_form->object));
            (*list)[list_length].object_type = get_policy_object_type(policies_form->object_type);
            (*list)[list_length].action = get_policy_action_type(policies_form->action);
            strcpy(NameStr((*list)[list_length].att_name), NameStr(policies_form->att_name));
            strcpy(NameStr((*list)[list_length].const_val), NameStr(policies_form->const_val));
            (*list)[list_length].policy_operator = get_policy_operator(policies_form->policy_operator);
            (*list)[list_length].tag = get_policy_tag(policies_form->tag);
            ++list_length;
        }
    }
    heap_endscan(scan);
    heap_close(rel, AccessShareLock);

    return false;
}

abacAttType get_type_by_name_from_att(const char *name)
{
    Relation rel = NULL;
    ScanKeyData skey[1];
    SysScanDesc scan = NULL;
    HeapTuple tuple = NULL;

    rel = heap_open(AttributesRelationId, RowExclusiveLock);
    ScanKeyInit(&skey[0],
                Anum_abac_attributes_name,
                BTEqualStrategyNumber,
                F_NAMEEQ,
                CStringGetDatum(name));
    scan = systable_beginscan(rel,
                              AbacAttributesNameIndexId,
                              true,
                              SnapshotNow,
                              1,
                              skey);
    tuple = systable_getnext(scan);
    if (!HeapTupleIsValid(tuple))
        ereport(ERROR, (errmsg("Cannot find the type corresponding to attribute \"%s\"", name)));

    abacAttType ret = get_att_type(((Form_abac_attributes)GETSTRUCT(tuple))->type);

    systable_endscan(scan);
    heap_close(rel, RowExclusiveLock);
    return ret;
}

static bool search_att(const char *object,
                       const abacAttManagerObjectType &object_type,
                       const char *att_name,
                       PATT *list,
                       size_t &list_length)
{
    list_length = 0;
    if (object == NULL || object[0] == '\0' ||
        att_name == NULL || att_name[0] == '\0')
        return false;

    if (*list != NULL)
        pfree(*list);
    *list = (PATT)palloc(sizeof(ATT));
    if (*list == NULL)
        ereport(ERROR, (errmsg("memory allocation failed")));

    size_t list_allocated_length = 1;
    abacAttType att_type = get_type_by_name_from_att(att_name);

    Relation rel = NULL;
    TableScanDesc scan = NULL;
    HeapTuple tuple = NULL;
    Form_abac_attributes_manager attributes_manager_form = NULL;
    rel = heap_open(AttributesManagerRelationId, AccessShareLock);
    scan = heap_beginscan(rel, SnapshotNow, 0, NULL);

    while ((tuple = heap_getnext(scan, ForwardScanDirection)) != NULL)
    {
        attributes_manager_form = (Form_abac_attributes_manager)GETSTRUCT(tuple);
        if (get_attmanager_object_type(attributes_manager_form->object_type) == object_type &&
            object_match(object, NameStr(attributes_manager_form->object), object_type) &&
            !strcmp(NameStr(attributes_manager_form->attribute_name), att_name))
        {
            if (list_length == list_allocated_length)
            {
                list_allocated_length *= 2;
                *list = (PATT)repalloc(*list, list_allocated_length * sizeof(ATT));
                if (*list == NULL)
                    ereport(ERROR, (errmsg("memory allocation failed")));
            }
            strcpy(NameStr((*list)[list_length].object), NameStr(attributes_manager_form->object));
            (*list)[list_length].object_type = object_type;
            strcpy(NameStr((*list)[list_length].att_name), NameStr(attributes_manager_form->attribute_name));
            (*list)[list_length].att_type = att_type;
            strcpy(NameStr((*list)[list_length].att_value), NameStr(attributes_manager_form->attribute_value));
            ++list_length;
        }
    }
    heap_endscan(scan);
    heap_close(rel, AccessShareLock);

    return false;
}

abacPolicyActionType get_action(AclMode mask)
{
    abacPolicyActionType action = ABAC_POLICY_ACTION_TYPE_ANY;
    if (mask & FLAG_FOR_DDL_ACL)
        ;
    else if (mask & ACL_DELETE)
        action = ABAC_POLICY_ACTION_TYPE_DELETE;
    else if (mask & ACL_UPDATE)
        action = ABAC_POLICY_ACTION_TYPE_UPDATE;
    else if (mask & ACL_INSERT)
        action = ABAC_POLICY_ACTION_TYPE_INSERT;
    else if (mask & ACL_SELECT)
        action = ABAC_POLICY_ACTION_TYPE_SELECT;
    return action;
}

static bool stringmatch(const char *rp, const char *rs)
{
	if (rp == NULL || rs == NULL)
		return false;
	size_t len_s = strlen(rs), len_rp = strlen(rp), len_p = 0;
	char *p = (char*)palloc(len_rp + 1);
	char *s = (char*)palloc(len_s + 1);
	if (p == NULL || s == NULL)
	{
		if (p == NULL)
			pfree(p);
		if (s == NULL)
			pfree(s);
		return false;
	}
	bool can = true;
	for (size_t i = 0; i < len_rp; ++i)
	{
		if (rp[i] == '\\')
		{
			if (i + 1 >= len_rp || !(rp[i + 1] == '*' || rp[i + 1] == '?' || rp[i + 1] == '\\'))
			{
				can = false;
				break;
			}
			p[len_p++] = -rp[++i];
		}
		else
			p[len_p++] = rp[i];
	}
	p[len_p] = '\0';
	if (!can)
	{
		pfree(p);
		pfree(s);
		return false;
	}
	for (size_t i = 0; i < len_s; ++i)
		if (rs[i] == '*' || rs[i] == '?' || rs[i] == '\\')
			s[i] = -rs[i];
		else
			s[i] = rs[i];
	s[len_s] = '\0';
	while (len_s && len_p && p[len_p - 1] != '*')
	{
		if (s[len_s - 1] == p[len_p - 1] || p[len_p - 1] == '?')
		{
			--len_s;
			--len_p;
		}
		else
		{
			can = false;
			break;
		}
	}
	if (!can || len_p == 0)
	{
		pfree(p);
		pfree(s);
		return can ? len_s == 0 : can;
	}
	size_t sIndex = 0, pIndex = 0;
	size_t sRecord = -1, pRecord = -1;
	while (sIndex < len_s && pIndex < len_p)
	{
		if (p[pIndex] == '*')
		{
			++pIndex;
			sRecord = sIndex;
			pRecord = pIndex;
		}
		else if (s[sIndex] == p[pIndex] || p[pIndex] == '?')
		{
			++sIndex;
			++pIndex;
		}
		else if (~sRecord && sRecord + 1 < len_s)
		{
			++sRecord;
			sIndex = sRecord;
			pIndex = pRecord;
		}
		else
		{
			can = false;
			break;
		}
	}
	for (size_t i = pIndex; can && i < len_p; ++i)
	{
		if (p[i] != '*')
		{
			can = false;
			break;
		}
	}
	pfree(p);
	pfree(s);
	return can;
}

static bool operator_in(const PATT list_left, size_t list_left_length,
                        const PATT list_right, size_t list_right_length,
                        const char *att_name)
{
    if (list_left == NULL || list_right == NULL || att_name == NULL)
        return false;

    if (!strcmp(att_name, "domain"))
    {
        int res;
        for (size_t i = 0; i < list_left_length; ++i)
        {
            for (size_t j = 0; j < list_right_length; ++j)
            {
                res = domaincmp(NameStr(list_left[i].att_value), NameStr(list_right[j].att_value));
                if (res == -2)
                    ereport(ERROR, (errmsg("compare domain %s and domain %s failed", NameStr(list_left[i].att_value), NameStr(list_right[i].att_value))));
                if (res == -1 || res == 0)
                    goto next1;
            }
            return false;
        next1:;
        }
        return true;
    }
    for (size_t i = 0; i < list_left_length; ++i)
    {
        for (size_t j = 0; j < list_right_length; ++j)
        {
            if (!strcmp(NameStr(list_left[i].att_value), NameStr(list_right[i].att_value)))
                goto next;
        }
        return false;
    next:;
    }
    return true;
}

static bool operator_not_in(const PATT list_left, size_t list_left_length,
                            const PATT list_right, size_t list_right_length, 
                            const char *att_name)
{
    if (list_left == NULL || list_right == NULL || att_name == NULL)
        return false;

    if (!strcmp(att_name, "domain"))
    {
        int res;
        for (size_t i = 0; i < list_left_length; ++i)
        {
            for (size_t j = 0; j < list_right_length; ++j)
            {
                res = domaincmp(NameStr(list_left[i].att_value), NameStr(list_right[j].att_value));
                if (res == -2)
                    ereport(ERROR, (errmsg("compare domain %s and domain %s failed", NameStr(list_left[i].att_value), NameStr(list_right[i].att_value))));
                if (res != 1 && res != -3)
                    return false;
            }
        }
        return true;
    }

    for (size_t i = 0; i < list_left_length; ++i)
    {
        for (size_t j = 0; j < list_right_length; ++j)
        {
            if (!strcmp(NameStr(list_left[i].att_value), NameStr(list_right[j].att_value)))
                return false;
        }
    }
    return true;
}

static void get_time(char *datetime)
{
    if (datetime == NULL)
        return;

    time_t now = time(0);
    tm *gmtm = localtime(&now);
    sprintf(datetime, "%02d:%02d:%02d", gmtm->tm_hour, gmtm->tm_min, gmtm->tm_sec);
}

static void get_date(char *date)
{
    if (date == NULL)
        return;

    time_t now = time(0);
    tm *gmtm = localtime(&now);
    sprintf(date, "%04d-%02d-%02d", gmtm->tm_year + 1900, gmtm->tm_mon + 1, gmtm->tm_mday);
}

static void get_weekday(char *weekday)
{
    if (weekday == NULL)
        return;

    time_t now = time(0);
    tm *gmtm = localtime(&now);
    if (gmtm->tm_wday == 0)
        sprintf(weekday, "%d", 7);
    else
        sprintf(weekday, "%d", gmtm->tm_wday);
}

static int Compare_SET(const PATT list_left,
                       size_t list_left_length,
                       const abacPolicyOperator &policy_opt,
                       const PATT &list_right,
                       size_t list_right_length,
                       const GaussPOLICY &policy)
{
    if (list_left == NULL || list_right == NULL || list_left[0].att_type != ABAC_ATT_SET)
        return 0;

    int result = 0;
    switch (policy_opt)
    {
    case ABAC_POLICY_OPERATOR_CONTAIN:
        result = (int)operator_in(list_left, list_left_length, list_right, list_right_length, NameStr(policy.att_name));
        break;
    case ABAC_POLICY_OPERATOR_NOT_CONTAIN:
        result = (int)operator_not_in(list_left, list_left_length, list_right, list_right_length, NameStr(policy.att_name));
        break;
    default:
        return 0;
    }
    return result;
}

static int Compare_STRING(const ATT &left,
                          const abacPolicyOperator &policy_opt,
                          const ATT &right,
                          const char *att_name)
{
    if (att_name == NULL)
        return false;

    bool state = false;
    int res;
    if (!strcmp(att_name, "level"))
    {
        res = levelcmp(NameStr(left.att_value), NameStr(right.att_value));
        if (res == -2)
            ereport(ERROR, (errmsg("compare level %s and level %s failed", NameStr(left.att_value), NameStr(right.att_value))));
        switch (policy_opt)
        {
        case ABAC_POLICY_OPERATOR_EQ:
            state = res == 0;
            break;
        case ABAC_POLICY_OPERATOR_LT:
            state = res == -1;
            break;
        case ABAC_POLICY_OPERATOR_NE:
            state = res != 0;
            break;
        case ABAC_POLICY_OPERATOR_LE:
            state = res <= 0;
            break;
        case ABAC_POLICY_OPERATOR_GT:
            state = res == 1;
            break;
        case ABAC_POLICY_OPERATOR_GE:
            state = res >= 0;
            break;
        default:
            return 0;
        }
        return (int)state;
    }

    switch (policy_opt)
    {
    case ABAC_POLICY_OPERATOR_EQ:
        state = strcmp(NameStr(left.att_value), NameStr(right.att_value)) == 0;
        break;
    case ABAC_POLICY_OPERATOR_LT:
        state = strcmp(NameStr(left.att_value), NameStr(right.att_value)) < 0;
        break;
    case ABAC_POLICY_OPERATOR_NE:
        state = strcmp(NameStr(left.att_value), NameStr(right.att_value)) != 0;
        break;
    case ABAC_POLICY_OPERATOR_LE:
        state = strcmp(NameStr(left.att_value), NameStr(right.att_value)) <= 0;
        break;
    case ABAC_POLICY_OPERATOR_GT:
        state = strcmp(NameStr(left.att_value), NameStr(right.att_value)) > 0;
        break;
    case ABAC_POLICY_OPERATOR_GE:
        state = strcmp(NameStr(left.att_value), NameStr(right.att_value)) >= 0;
        break;
    case ABAC_POLICY_OPERATOR_LIKE:
        state = stringmatch(NameStr(right.att_value), NameStr(left.att_value));
        break;
    default:
        state = false;
    }
    return (int)state;
}

static int Compare_INT(const ATT &left,
                       const abacPolicyOperator &policy_opt,
                       const ATT &right)
{
    bool state = false;
    switch (policy_opt)
    {
    case ABAC_POLICY_OPERATOR_EQ:
        state = atoi(NameStr(left.att_value)) == atoi(NameStr(right.att_value));
        break;
    case ABAC_POLICY_OPERATOR_LT:
        state = atoi(NameStr(left.att_value)) < atoi(NameStr(right.att_value));
        break;
    case ABAC_POLICY_OPERATOR_NE:
        state = atoi(NameStr(left.att_value)) != atoi(NameStr(right.att_value));
        break;
    case ABAC_POLICY_OPERATOR_LE:
        state = atoi(NameStr(left.att_value)) <= atoi(NameStr(right.att_value));
        break;
    case ABAC_POLICY_OPERATOR_GT:
        state = atoi(NameStr(left.att_value)) > atoi(NameStr(right.att_value));
        break;
    case ABAC_POLICY_OPERATOR_GE:
        state = atoi(NameStr(left.att_value)) >= atoi(NameStr(right.att_value));
        break;
    default:
        state = false;
    }
    return (int)state;
}

static int Compare_DOUBLE(const ATT &left,
                          const abacPolicyOperator &policy_opt,
                          const ATT &right)
{
    bool state = false;

    switch (policy_opt)
    {
    case ABAC_POLICY_OPERATOR_EQ:
        state = fabs(atof(NameStr(left.att_value)) - atof(NameStr(right.att_value))) < 1e-7;
        break;
    case ABAC_POLICY_OPERATOR_LT:
        state = atof(NameStr(left.att_value)) < atof(NameStr(right.att_value));
        break;
    case ABAC_POLICY_OPERATOR_NE:
        state = fabs(atof(NameStr(left.att_value)) - atof(NameStr(right.att_value))) >= 1e-7;
        break;
    case ABAC_POLICY_OPERATOR_LE:
        state = atof(NameStr(left.att_value)) < atof(NameStr(right.att_value)) + 1e-7;
        break;
    case ABAC_POLICY_OPERATOR_GT:
        state = atof(NameStr(left.att_value)) > atof(NameStr(right.att_value));
        break;
    case ABAC_POLICY_OPERATOR_GE:
        state = atof(NameStr(left.att_value)) + 1e-7 > atof(NameStr(right.att_value));
        break;
    default:
        return 0;
    }
    return (int)state;
}

static int Compare_BOOL(const ATT &left,
                        const abacPolicyOperator &policy_opt,
                        const ATT &right)
{
    bool state = false;

    switch (policy_opt)
    {
    case ABAC_POLICY_OPERATOR_EQ:
		state = strcmp(NameStr(left.att_value), NameStr(right.att_value)) == 0;
        break;
    case ABAC_POLICY_OPERATOR_NE:
		state = strcmp(NameStr(left.att_value), NameStr(right.att_value)) != 0;
        break;
    default:
        return 0;
    }
    return (int)state;
}

static int base_operation(const PATT list_left,
                          size_t list_left_length,
                          const abacPolicyOperator &policy_opt,
                          const PATT list_right,
                          size_t list_right_length,
                          const GaussPOLICY &policy)
{
    if (list_left == NULL || list_right == NULL)
        return 0;

    int result = 0;
    for (size_t i = 0; i < list_left_length; ++i)
    {
        for (size_t j = 0; j < list_right_length; ++j)
        {
            switch (list_left[0].att_type)
            {
            case ABAC_ATT_DATE:
            case ABAC_ATT_DATETIME:
            case ABAC_ATT_STRING:
                result = Compare_STRING(list_left[i], policy_opt,
                                        list_right[j], NameStr(policy.att_name));
                break;
            case ABAC_ATT_INT:
                result = Compare_INT(list_left[i], policy_opt, list_right[j]);
                break;
            case ABAC_ATT_DOUBLE:
                result = Compare_DOUBLE(list_left[i], policy_opt, list_right[j]);
				break;
			case ABAC_ATT_BOOL:
				result = Compare_BOOL(list_left[i], policy_opt, list_right[j]);
				break;
            default:
                return 0;
            }
        }
    }
    return result;
}

static int analysis(const char *subject, const abacAttManagerObjectType &subject_type,
                    const char *object, const abacAttManagerObjectType &object_type,
                    const GaussPOLICY &policy, const char *s_ip)
{
    if (subject == NULL || object == NULL || s_ip == NULL)
        return 0;

    int result = -1;
    PATT list_left = NULL, list_right = NULL;
    size_t list_left_length = 0, list_right_length = 0;

    switch (policy.tag)
    {
    case ABAC_POLICY_TAG_ATTRIBUTE_ATTRIBUTE:
    {
        search_att(subject, subject_type, NameStr(policy.att_name), &list_left, list_left_length);
        if (list_left_length == 0)
        {
            result = 0;
            break;
        }

        search_att(object, object_type, NameStr(policy.att_name), &list_right, list_right_length);
        if (list_right_length == 0)
        {
            result = 1;
            break;
        }
    }
    break;
    case ABAC_POLICY_TAG_ATTRIBUTE_VALUE:
    {
        search_att(subject, subject_type, NameStr(policy.att_name), &list_left, list_left_length);
        if (list_left_length == 0)
        {
            result = 0;
            break;
        }

        list_right = (PATT)palloc(sizeof(GaussPOLICY));
        strcpy(NameStr(list_right[list_right_length].object), NameStr(policy.object));
        list_right[list_right_length].object_type = subject_type;
        strcpy(NameStr(list_right[list_right_length].att_name), NameStr(policy.att_name));
        list_right[list_right_length].att_type = list_left[0].att_type;
        strcpy(NameStr(list_right[list_right_length].att_value), NameStr(policy.const_val));
        ++list_right_length;
    }
    break;
    case ABAC_POLICY_TAG_ENVIRONMENT_VALUE:
    {
        abacAttType att_type = get_type_by_name_from_att(NameStr(policy.att_name));
        if ((att_type != ABAC_ATT_STRING) && (att_type != ABAC_ATT_DATETIME) && (att_type != ABAC_ATT_DATE) && (att_type != ABAC_ATT_INT))
        {
            result = 0;
            break;
        }

        list_left = (PATT)palloc(sizeof(GaussPOLICY));
        strcpy(NameStr(list_left[list_left_length].object), NameStr(policy.object));
        list_left[list_left_length].object_type = subject_type;
        strcpy(NameStr(list_left[list_left_length].att_name), NameStr(policy.att_name));
        list_left[list_left_length].att_type = att_type;

        if (!strcmp(NameStr(policy.att_name), "ip"))
            strcpy(NameStr(list_left[list_left_length].att_value), s_ip);
        else if (!strcmp(NameStr(policy.att_name), "time"))
        {
            char *time = (char *)palloc(TIME_LENGTH + 1);
            if (time == NULL)
            {
                pfree(list_left);
                ereport(ERROR, (errmsg("memory allocation failed")));
            }
            get_time(time);
            strcpy(NameStr(list_left[list_left_length].att_value), time);
            pfree(time);
        }
        else if (!strcmp(NameStr(policy.att_name), "date"))
        {
            char *date = (char *)palloc(DATE_LENGTH + 1);
            if (date == NULL)
            {
                pfree(list_left);
                ereport(ERROR, (errmsg("memory allocation failed")));
            }
            get_date(date);
            strcpy(NameStr(list_left[list_left_length].att_value), date);
            pfree(date);
        }
        else if (!strcmp(NameStr(policy.att_name), "weekday"))
        {
            char *weekday = (char *)palloc(WEEKDAY_LENGTH + 1);
            if (weekday == NULL)
            {
                pfree(list_left);
                ereport(ERROR, (errmsg("memory allocation failed")));
            }
            get_weekday(weekday);
            strcpy(NameStr(list_left[list_left_length].att_value), weekday);
            pfree(weekday);
        }
        else
        {
            result = 0;
            break;
        }
        ++list_left_length;

        list_right = (PATT)palloc(sizeof(GaussPOLICY));
        strcpy(NameStr(list_right[list_right_length].object), NameStr(policy.object));
        list_right[list_right_length].object_type = object_type;
        strcpy(NameStr(list_right[list_right_length].att_name), NameStr(policy.att_name));
        strcpy(NameStr(list_right[list_right_length].att_value), NameStr(policy.const_val));
        list_right[list_right_length].att_type = att_type;
        ++list_right_length;
    }
    break;
    default:
        result = 0;
    }
    if (~result)
    {
        if (list_left != NULL)
            pfree(list_left);
        if (list_right != NULL)
            pfree(list_right);
        return result;
    }

    abacPolicyOperator policy_opt = policy.policy_operator;

    switch (policy_opt)
    {
    case ABAC_POLICY_OPERATOR_CONTAIN:
    case ABAC_POLICY_OPERATOR_NOT_CONTAIN:
        result = Compare_SET(list_right, list_right_length, policy_opt, list_left, list_left_length, policy);
        break;
    case ABAC_POLICY_OPERATOR_EQ:
    case ABAC_POLICY_OPERATOR_LT:
    case ABAC_POLICY_OPERATOR_NE:
    case ABAC_POLICY_OPERATOR_LE:
    case ABAC_POLICY_OPERATOR_GT:
    case ABAC_POLICY_OPERATOR_GE:
    case ABAC_POLICY_OPERATOR_LIKE:
        result = base_operation(list_left, list_left_length, policy_opt, list_right, list_right_length, policy);
        break;
    default:
        result = 0;
    }
    if (list_left != NULL)
        pfree(list_left);
    if (list_right != NULL)
        pfree(list_right);
    return result;
}

int policyDecision(const char *subject, const abacAttManagerObjectType &subject_type,
                   const char *object, const abacAttManagerObjectType &object_type,
                   const GaussPOLICY &policy, const char *s_ip)
{
    if (subject == NULL || object == NULL || s_ip == NULL)
        return false;

    int ret = 0;
    switch (policy.tag)
    {
	
    case ABAC_POLICY_TAG_ATTRIBUTE_ATTRIBUTE:
    case ABAC_POLICY_TAG_ATTRIBUTE_VALUE:
    case ABAC_POLICY_TAG_ENVIRONMENT_VALUE:
        ret = analysis(subject, subject_type,
                       object, object_type,
                       policy, s_ip);
        break;
    default:
        return 0;
    }
    return ret;
}
