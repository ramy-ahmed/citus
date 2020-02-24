/*-------------------------------------------------------------------------
 *
 * role.c
 *    Commands for ALTER ROLE statements.
 *
 * Copyright (c) Citus Data, Inc.
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/heapam.h"
#include "access/htup_details.h"
#if PG_VERSION_NUM >= 120000
#include "access/table.h"
#endif
#include "catalog/catalog.h"
#include "catalog/pg_authid.h"
#include "catalog/pg_db_role_setting.h"
#include "commands/dbcommands.h"
#include "distributed/citus_ruleutils.h"
#include "distributed/commands.h"
#include "distributed/commands/utility_hook.h"
#include "distributed/deparser.h"
#include "distributed/listutils.h"
#include "distributed/master_protocol.h"
#include "distributed/worker_transaction.h"
#include "miscadmin.h"
#include "nodes/makefuncs.h"
#include "nodes/parsenodes.h"
#include "nodes/pg_list.h"
#include "utils/acl.h"
#include "utils/builtins.h"
#include "utils/rel.h"
#include "utils/syscache.h"

static const char * ExtractEncryptedPassword(Oid roleOid);
static void ErrorIfUnsupportedAlterRoleSetStmt(AlterRoleSetStmt *stmt);
static const char * CreateAlterRoleIfExistsCommand(AlterRoleStmt *stmt);
static char * CreateAlterRoleSetIfExistsCommand(AlterRoleSetStmt *stmt);
static DefElem * makeDefElemInt(char *name, int value);

char * GetRoleNameFromDbRoleSetting(HeapTuple tuple, TupleDesc DbRoleSettingDescription);
char * GetDatabaseNameFromDbRoleSetting(HeapTuple tuple,
										TupleDesc DbRoleSettingDescription);
Node * makeStringConst(char *str, int location);
char * WrapQueryInAlterRoleIfExistsCall(char *query, RoleSpec *role);

/* controlled via GUC */
bool EnableAlterRolePropagation = false;

/*
 * PostprocessAlterRoleStmt actually creates the plan we need to execute for alter
 * role statement. We need to do it this way because we need to use the encrypted
 * password, which is, in some cases, created at standardProcessUtility.
 */
List *
PostprocessAlterRoleStmt(Node *node, const char *queryString)
{
	AlterRoleStmt *stmt = castNode(AlterRoleStmt, node);

	if (!EnableAlterRolePropagation || !IsCoordinator())
	{
		return NIL;
	}

	/*
	 * Make sure that no new nodes are added after this point until the end of the
	 * transaction by taking a RowShareLock on pg_dist_node, which conflicts with the
	 * ExclusiveLock taken by master_add_node.
	 */
	LockRelationOid(DistNodeRelationId(), RowShareLock);

	DefElem *option = NULL;
	foreach_ptr(option, stmt->options)
	{
		if (strcasecmp(option->defname, "password") == 0)
		{
			Oid roleOid = get_rolespec_oid(stmt->role, true);
			const char *encryptedPassword = ExtractEncryptedPassword(roleOid);

			if (encryptedPassword != NULL)
			{
				Value *encryptedPasswordValue = makeString((char *) encryptedPassword);
				option->arg = (Node *) encryptedPasswordValue;
			}
			else
			{
				option->arg = NULL;
			}

			break;
		}
	}
	List *commands = list_make1((void *) CreateAlterRoleIfExistsCommand(stmt));

	return NodeDDLTaskList(ALL_WORKERS, commands);
}


/*
 * PreprocessAlterRoleSetStmt actually creates the plan we need to execute for alter
 * role set statement.
 */
List *
PreprocessAlterRoleSetStmt(Node *node, const char *queryString)
{
	if (!EnableAlterRolePropagation)
	{
		return NIL;
	}

	AlterRoleSetStmt *stmt = castNode(AlterRoleSetStmt, node);
	ErrorIfUnsupportedAlterRoleSetStmt(stmt);

	EnsureCoordinator();
	QualifyTreeNode((Node *) stmt);
	const char *sql = DeparseTreeNode((Node *) stmt);

	List *commandList = list_make1((void *) sql);

	return NodeDDLTaskList(ALL_WORKERS, commandList);
}


/*
 * ErrorIfUnsupportedAlterRoleSetStmt raises an error if the AlterRoleSetStmt contains a
 * construct that is not supported.
 *
 * Unsupported Constructs:
 *  - ALTER ROLE ... SET ... FROM CURRENT
 */
static void
ErrorIfUnsupportedAlterRoleSetStmt(AlterRoleSetStmt *stmt)
{
	VariableSetStmt *setStmt = stmt->setstmt;

	if (setStmt->kind == VAR_SET_CURRENT)
	{
		/* check if the set action is a SET ... FROM CURRENT */
		ereport(WARNING, (errmsg("not propagating ALTER ROLE .. SET .. FROM"
								 " CURRENT command to worker nodes"),
						  errhint("SET FROM CURRENT is not supported for "
								  "distributed users, instead use the SET ... "
								  "TO ... syntax with a constant value.")));
	}
}


/*
 * CreateAlterRoleIfExistsCommand creates ALTER ROLE command, from the alter role node
 *  using the alter_role_if_exists() UDF.
 */
static const char *
CreateAlterRoleIfExistsCommand(AlterRoleStmt *stmt)
{
	char *alterRoleQuery = DeparseTreeNode((Node *) stmt);
	return WrapQueryInAlterRoleIfExistsCall(alterRoleQuery, stmt->role);
}


/*
 * CreateAlterRoleSetIfExistsCommand creates ALTER ROLE .. SET command, from the
 * AlterRoleSetStmt node.
 *
 * If the statement affects a single user, the query is wrapped in a
 * alter_role_if_exists() to make sure that it is run on workers that has a user
 * with the same name. If the query is a ALTER ROLE ALL .. SET query, the query
 * is sent to the workers as is.
 */
static char *
CreateAlterRoleSetIfExistsCommand(AlterRoleSetStmt *stmt)
{
	char *alterRoleSetQuery = DeparseTreeNode((Node *) stmt);

	/* ALTER ROLE ALL .. SET queries should not be wrapped in a alter_role_if_exists() call */
	if (stmt->role == NULL)
	{
		return alterRoleSetQuery;
	}
	else
	{
		return WrapQueryInAlterRoleIfExistsCall(alterRoleSetQuery, stmt->role);
	}
}


/*
 * WrapQueryInAlterRoleIfExistsCall wraps a given query in a alter_role_if_exists()
 * UDF.
 */
char *
WrapQueryInAlterRoleIfExistsCall(char *query, RoleSpec *role)
{
	StringInfoData buffer = { 0 };

	const char *roleName = RoleSpecString(role, false);
	initStringInfo(&buffer);
	appendStringInfo(&buffer,
					 "SELECT alter_role_if_exists(%s, %s)",
					 quote_literal_cstr(roleName),
					 quote_literal_cstr(query));

	return buffer.data;
}


/*
 * ExtractEncryptedPassword extracts the encrypted password of a role. The function
 * gets the password from the pg_authid table.
 */
static const char *
ExtractEncryptedPassword(Oid roleOid)
{
	Relation pgAuthId = heap_open(AuthIdRelationId, AccessShareLock);
	TupleDesc pgAuthIdDescription = RelationGetDescr(pgAuthId);
	HeapTuple tuple = SearchSysCache1(AUTHOID, roleOid);
	bool isNull = true;

	if (!HeapTupleIsValid(tuple))
	{
		return NULL;
	}

	Datum passwordDatum = heap_getattr(tuple, Anum_pg_authid_rolpassword,
									   pgAuthIdDescription, &isNull);

	heap_close(pgAuthId, AccessShareLock);
	ReleaseSysCache(tuple);

	if (isNull)
	{
		return NULL;
	}

	return pstrdup(TextDatumGetCString(passwordDatum));
}


/*
 * GenerateAlterRoleSetIfExistsCommandList generate a list of ALTER ROLE .. SET commands that
 * copies a role session defaults from the pg_db_role_settings table.
 */
static List *
GenerateAlterRoleSetIfExistsCommandList(HeapTuple tuple, TupleDesc
										DbRoleSettingDescription)
{
	AlterRoleSetStmt *stmt = makeNode(AlterRoleSetStmt);
	const char *currentDatabaseName = CurrentDatabaseName();
	List *commandList = NIL;

	bool isnull;

	/* Datum		setrole, setdatabase, setconfig; */

	const char *databaseName =
		GetDatabaseNameFromDbRoleSetting(tuple, DbRoleSettingDescription);

	/*
	 * session defaults for databases other than the current one are skipped
	 */
	if (databaseName != NULL &&
		pg_strcasecmp(databaseName, currentDatabaseName) != 0)
	{
		return NULL;
	}

	if (databaseName != NULL)
	{
		stmt->database = pstrdup(databaseName);
	}

	const char *roleName = GetRoleNameFromDbRoleSetting(tuple, DbRoleSettingDescription);

	/*
	 * default roles are skipped, because reserved roles
	 * cannot be altered.
	 */
	if (roleName != NULL && IsReservedName(roleName))
	{
		return NULL;
	}

	if (roleName != NULL)
	{
		stmt->role = makeNode(RoleSpec);
		stmt->role->location = -1;
		stmt->role->roletype = ROLESPEC_CSTRING;
		stmt->role->rolename = pstrdup(roleName);
	}

	Datum setconfig = heap_getattr(tuple, Anum_pg_db_role_setting_setconfig,
								   DbRoleSettingDescription, &isnull);
	ArrayType *array = DatumGetArrayTypeP(setconfig);
	int i;

	for (i = 1; i <= ARR_DIMS(array)[0]; i++)
	{
		Datum d = array_ref(array, 1, &i,
							-1 /* varlenarray */,
							-1 /* TEXT's typlen */,
							false /* TEXT's typbyval */,
							'i' /* TEXT's typalign */,
							&isnull);
		if (isnull)
		{
			continue;
		}
		char *configItem = TextDatumGetCString(d);

		char *pos = strchr(configItem, '=');
		if (pos == NULL)
		{
			continue;
		}
		*pos++ = '\0';

		stmt->setstmt = makeNode(VariableSetStmt);
		stmt->setstmt->kind = VAR_SET_VALUE;
		stmt->setstmt->name = pstrdup(configItem);

		/* TODO add support for const values that are not strings */
		stmt->setstmt->args = list_make1(makeStringConst(pos, -1));

		commandList = lappend(commandList, CreateAlterRoleSetIfExistsCommand(stmt));
	}
	return commandList;
}


/*
 * GenerateAlterRoleIfExistsCommand generate ALTER ROLE command that copies a role from
 * the pg_authid table.
 */
static const char *
GenerateAlterRoleIfExistsCommand(HeapTuple tuple, TupleDesc pgAuthIdDescription)
{
	char *rolPassword = "";
	char *rolValidUntil = "infinity";
	bool isNull = true;
	Form_pg_authid role = ((Form_pg_authid) GETSTRUCT(tuple));
	AlterRoleStmt *stmt = makeNode(AlterRoleStmt);
	const char *rolename = NameStr(role->rolname);

	stmt->role = makeNode(RoleSpec);
	stmt->role->roletype = ROLESPEC_CSTRING;
	stmt->role->location = -1;
	stmt->role->rolename = pstrdup(rolename);
	stmt->action = 1;
	stmt->options = NIL;

	stmt->options =
		lappend(stmt->options,
				makeDefElemInt("superuser", role->rolsuper));

	stmt->options =
		lappend(stmt->options,
				makeDefElemInt("createdb", role->rolcreatedb));

	stmt->options =
		lappend(stmt->options,
				makeDefElemInt("createrole", role->rolcreaterole));

	stmt->options =
		lappend(stmt->options,
				makeDefElemInt("inherit", role->rolinherit));

	stmt->options =
		lappend(stmt->options,
				makeDefElemInt("canlogin", role->rolcanlogin));

	stmt->options =
		lappend(stmt->options,
				makeDefElemInt("isreplication", role->rolreplication));

	stmt->options =
		lappend(stmt->options,
				makeDefElemInt("bypassrls", role->rolbypassrls));


	stmt->options =
		lappend(stmt->options,
				makeDefElemInt("connectionlimit", role->rolconnlimit));


	Datum rolPasswordDatum = heap_getattr(tuple, Anum_pg_authid_rolpassword,
										  pgAuthIdDescription, &isNull);
	if (!isNull)
	{
		rolPassword = pstrdup(TextDatumGetCString(rolPasswordDatum));
		stmt->options = lappend(stmt->options, makeDefElem("password",
														   (Node *) makeString(
															   rolPassword),
														   -1));
	}
	else
	{
		stmt->options = lappend(stmt->options, makeDefElem("password", NULL, -1));
	}

	Datum rolValidUntilDatum = heap_getattr(tuple, Anum_pg_authid_rolvaliduntil,
											pgAuthIdDescription, &isNull);
	if (!isNull)
	{
		rolValidUntil = pstrdup((char *) timestamptz_to_str(rolValidUntilDatum));
	}

	stmt->options = lappend(stmt->options, makeDefElem("validUntil",
													   (Node *) makeString(rolValidUntil),
													   -1));

	return CreateAlterRoleIfExistsCommand(stmt);
}


/*
 * GenerateAlterRoleIfExistsCommandAllRoles creates ALTER ROLE commands
 * that copies all roles from the pg_authid table.
 */
List *
GenerateAlterRoleIfExistsCommandAllRoles()
{
	Relation pgAuthId = heap_open(AuthIdRelationId, AccessShareLock);
	TupleDesc pgAuthIdDescription = RelationGetDescr(pgAuthId);
	HeapTuple tuple = NULL;
	List *commands = NIL;
	const char *alterRoleQuery = NULL;

#if PG_VERSION_NUM >= 120000
	TableScanDesc scan = table_beginscan_catalog(pgAuthId, 0, NULL);
#else
	HeapScanDesc scan = heap_beginscan_catalog(pgAuthId, 0, NULL);
#endif

	while ((tuple = heap_getnext(scan, ForwardScanDirection)) != NULL)
	{
		const char *rolename = NameStr(((Form_pg_authid) GETSTRUCT(tuple))->rolname);

		/*
		 * The default roles are skipped, because reserved roles
		 * cannot be altered.
		 */
		if (IsReservedName(rolename))
		{
			continue;
		}
		alterRoleQuery = GenerateAlterRoleIfExistsCommand(tuple, pgAuthIdDescription);
		commands = lappend(commands, (void *) alterRoleQuery);
	}

	heap_endscan(scan);
	heap_close(pgAuthId, AccessShareLock);

	return commands;
}


/*
 * GenerateAlterRoleSetIfExistsCommandAllRoles creates ALTER ROLE .. SET commands
 * that copies all session defaults for roles from the pg_db_role_setting table.
 */
List *
GenerateAlterRoleSetIfExistsCommandAllRoles()
{
	Relation DbRoleSetting = heap_open(DbRoleSettingRelationId, AccessShareLock);
	TupleDesc DbRoleSettingDescription = RelationGetDescr(DbRoleSetting);
	HeapTuple tuple = NULL;
	List *commands = NIL;
	List *alterRoleSetQueries = NIL;


#if PG_VERSION_NUM >= 120000
	TableScanDesc scan = table_beginscan_catalog(DbRoleSetting, 0, NULL);
#else
	HeapScanDesc scan = heap_beginscan_catalog(DbRoleSetting, 0, NULL);
#endif

	while ((tuple = heap_getnext(scan, ForwardScanDirection)) != NULL)
	{
		alterRoleSetQueries =
			GenerateAlterRoleSetIfExistsCommandList(tuple, DbRoleSettingDescription);

		commands = list_concat(commands, (void *) alterRoleSetQueries);
	}

	heap_endscan(scan);
	heap_close(DbRoleSetting, AccessShareLock);

	return commands;
}


/*
 * makeDefElemInt creates a DefElem with integer typed value with -1 as location.
 */
static DefElem *
makeDefElemInt(char *name, int value)
{
	return makeDefElem(name, (Node *) makeInteger(value), -1);
}


/*
 * GetDatabaseNameFromDbRoleSetting performs a lookup, and finds the database name
 * associated with a Role Setting
 */
char *
GetDatabaseNameFromDbRoleSetting(HeapTuple tuple, TupleDesc DbRoleSettingDescription)
{
	bool isnull;

	Datum setdatabase = heap_getattr(tuple, Anum_pg_db_role_setting_setdatabase,
									 DbRoleSettingDescription, &isnull);

	if (isnull)
	{
		return NULL;
	}

	Oid databaseId = DatumGetObjectId(setdatabase);
	char *databaseName = get_database_name(databaseId);

	return databaseName;
}


/*
 * GetDatabaseNameFromDbRoleSetting performs a lookup, and finds the role name
 * associated with a Role Setting
 */
char *
GetRoleNameFromDbRoleSetting(HeapTuple tuple, TupleDesc DbRoleSettingDescription)
{
	bool isnull;

	Datum setrole = heap_getattr(tuple, Anum_pg_db_role_setting_setrole,
								 DbRoleSettingDescription, &isnull);

	if (isnull)
	{
		return NULL;
	}

	Oid roleId = DatumGetObjectId(setrole);
	char *roleName = GetUserNameFromId(roleId, true);

	return roleName;
}


/*
 * makeStringConst creates a Const Node that stores a given string
 *
 * copied from backend/parser/gram.c
 */
Node *
makeStringConst(char *str, int location)
{
	A_Const *n = makeNode(A_Const);

	n->val.type = T_String;
	n->val.val.str = str;
	n->location = location;

	return (Node *) n;
}
