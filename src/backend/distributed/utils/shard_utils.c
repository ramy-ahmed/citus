/*-------------------------------------------------------------------------
 *
 * shard_utils.c
 *
 * This file contains functions to perform useful operations on shards.
 *
 * Copyright (c) Citus Data, Inc.
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"
#include "utils/lsyscache.h"
#include "distributed/metadata_cache.h"
#include "distributed/relay_utility.h"
#include "distributed/shard_utils.h"

/*
 * GetShardLocalTableOid returns the oid of the shard from the given distributed
 * relation with the shardId.
 */
Oid
GetShardLocalTableOid(Oid citusTableOid, uint64 shardId)
{
	const char *citusTableName = get_rel_name(citusTableOid);

	Assert(citusTableName != NULL);

	/* construct shard relation name */
	char *shardRelationName = pstrdup(citusTableName);
	AppendShardIdToName(&shardRelationName, shardId);

	Oid citusTableSchemaOid = get_rel_namespace(citusTableOid);

	Oid shardRelationOid = get_relname_relid(shardRelationName, citusTableSchemaOid);

	return shardRelationOid;
}


/*
 * GetOnlyShardOidOfReferenceTable returns OID of the one and only placement
 * of the given reference table. Caller of this function must ensure that
 * referenceTableOid is owned by a reference table.
 */
Oid
GetOnlyShardOidOfReferenceTable(Oid referenceTableOid)
{
	const CitusTableCacheEntry *cacheEntry = GetCitusTableCacheEntry(referenceTableOid);

	/* given OID should belong to a valid reference table */
	Assert(cacheEntry != NULL && cacheEntry->shardIntervalArrayLength == 1);
	Assert(cacheEntry->sortedShardIntervalArray != NULL &&
		   cacheEntry->sortedShardIntervalArray[0] != NULL);

	const ShardInterval *shardInterval = cacheEntry->sortedShardIntervalArray[0];
	uint64 referenceTableShardId = shardInterval->shardId;

	return GetShardLocalTableOid(referenceTableOid, referenceTableShardId);
}
