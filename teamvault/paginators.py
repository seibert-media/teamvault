from django.core.paginator import Paginator
from django.db import connections
from django.db.models import QuerySet
from django.utils.functional import cached_property


class EstimatingPaginator(Paginator):
    """Paginator that answers `count` from Postgres' own statistics.

    Django's default Paginator runs COUNT(*) over the full table on every page
    view, which grows with table size (up to ~500ms at 3.3M audit log rows).
    For an unfiltered queryset the exact number of rows does not matter for
    paging, so this paginator reads the fresher of two statistics instead:

    - pg_stat n_live_tup: counted per committed insert/delete by the
      cumulative statistics system, lags reality by seconds, but is reset
      by a stats reset or crash recovery
    - pg_class.reltuples: sampled by autovacuum/ANALYZE, survives restarts,
      but lags by up to autovacuum_analyze_scale_factor (default 10%)

    On insert-mostly tables both only ever undercount, so GREATEST picks the
    fresher one. On delete-heavy tables it would favor the staler OVERcount.
    For this reason, *only* ever use this Paginator for append-only models,
    like the auditlog.

    We fall back to a normal COUNT(*) when the object_list is not a queryset,
    when the queryset contains a "WHERE" (filter()/exclude()), or when both
    statistics are untrustworthy (<= 0).
    """

    @cached_property
    def count(self):
        estimate = self._estimated_count()
        if estimate is not None:
            return estimate
        return super().count

    def _estimated_count(self):
        queryset = self.object_list
        if not isinstance(queryset, QuerySet) or queryset.query.where:
            return None
        db_connection = connections[queryset.db]
        if db_connection.vendor != 'postgresql':
            return None
        with db_connection.cursor() as cursor:
            cursor.execute(
                'SELECT GREATEST(c.reltuples::bigint, COALESCE(s.n_live_tup, 0)) '
                'FROM pg_class c '
                'LEFT JOIN pg_stat_all_tables s ON s.relid = c.oid '
                'WHERE c.oid = %s::regclass',
                [queryset.model._meta.db_table],
            )
            estimate = cursor.fetchone()[0]

        # 0 here means both statistics are missing or stale-empty (reltuples
        # is -1 until the first ANALYZE, n_live_tup 0 after a stats reset)
        return estimate if estimate > 0 else None
