"""Caching layer for skill metadata to improve load performance"""

import json
import hashlib
import logging
from pathlib import Path
from typing import Dict, Optional
import pickle

logger = logging.getLogger(__name__)


class SkillMetadataCache:
    """
    Caches parsed skill metadata to disk to avoid re-parsing on every load.

    Format: Binary pickle files for speed, with file modification time tracking.
    Strategy: Cache entry is valid if source .md file hasn't changed.
    """

    def __init__(self, cache_dir: str = "/tmp/work/cache"):
        """
        Initialize the cache.

        Args:
            cache_dir: Directory to store cache files
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.stats = {
            'hits': 0,
            'misses': 0,
            'writes': 0,
            'errors': 0
        }

    def _get_cache_path(self, skill_file: Path) -> Path:
        """
        Generate cache filename from skill file path.

        Uses MD5 hash of full path to create consistent, portable cache names.

        Args:
            skill_file: Path to SKILL.md file

        Returns:
            Path to cache file
        """
        # Create hash from full path for portability
        file_hash = hashlib.md5(str(skill_file.resolve()).encode()).hexdigest()[:8]
        skill_name = skill_file.parent.name
        return self.cache_dir / f"skill_{skill_name}_{file_hash}.cache"

    def _get_file_mtime(self, skill_file: Path) -> float:
        """
        Get file modification time for cache invalidation.

        Args:
            skill_file: Path to file

        Returns:
            Modification time as float timestamp
        """
        try:
            return skill_file.stat().st_mtime
        except OSError as e:
            logger.error(f"Cannot stat file {skill_file}: {e}")
            return -1

    def get(self, skill_file: Path):
        """
        Retrieve cached metadata if cache is valid.

        A cache entry is valid if:
        1. Cache file exists
        2. Source file hasn't been modified since cache was written

        Args:
            skill_file: Path to SKILL.md file

        Returns:
            Metadata object if valid cache found, None otherwise
        """
        cache_path = self._get_cache_path(skill_file)

        if not cache_path.exists():
            self.stats['misses'] += 1
            return None

        try:
            with open(cache_path, 'rb') as f:
                cached_data = pickle.load(f)

            # Validate cache freshness by checking source file mtime
            current_mtime = self._get_file_mtime(skill_file)
            cached_mtime = cached_data.get('file_mtime', -1)

            if cached_mtime == current_mtime:
                self.stats['hits'] += 1
                logger.debug(f"Cache HIT for {skill_file.parent.name}")
                return cached_data.get('metadata')

            # Cache is stale, delete it
            logger.debug(f"Cache stale for {skill_file.parent.name} (mtime mismatch)")
            cache_path.unlink(missing_ok=True)
            self.stats['misses'] += 1
            return None

        except Exception as e:
            logger.warning(f"Cache read error for {cache_path}: {e}")
            self.stats['errors'] += 1
            # Don't crash, just return None to force re-parse
            return None

    def set(self, skill_file: Path, metadata):
        """
        Cache parsed metadata to disk.

        Args:
            skill_file: Path to SKILL.md file
            metadata: SkillMetadata object to cache
        """
        cache_path = self._get_cache_path(skill_file)

        try:
            cached_data = {
                'file_mtime': self._get_file_mtime(skill_file),
                'metadata': metadata,
                'cached_at': __import__('time').time()
            }
            with open(cache_path, 'wb') as f:
                pickle.dump(cached_data, f)
            self.stats['writes'] += 1
            logger.debug(f"Cache written for {skill_file.parent.name}")
        except Exception as e:
            logger.warning(f"Cache write error for {cache_path}: {e}")
            self.stats['errors'] += 1

    def invalidate(self, skill_file: Path):
        """
        Explicitly invalidate cache for a specific skill file.

        Args:
            skill_file: Path to SKILL.md file
        """
        cache_path = self._get_cache_path(skill_file)
        try:
            cache_path.unlink(missing_ok=True)
            logger.info(f"Cache invalidated for {skill_file.parent.name}")
        except Exception as e:
            logger.warning(f"Error invalidating cache: {e}")

    def clear(self):
        """
        Clear entire cache directory.

        Use with caution - removes all cached skill metadata.
        """
        try:
            for cache_file in self.cache_dir.glob("skill_*.cache"):
                cache_file.unlink()
            logger.info(f"Cache cleared: {self.cache_dir}")
            self.stats = {
                'hits': 0,
                'misses': 0,
                'writes': 0,
                'errors': 0
            }
        except Exception as e:
            logger.error(f"Error clearing cache: {e}")

    def get_stats(self) -> Dict:
        """
        Get cache performance statistics.

        Returns:
            Dictionary with hits, misses, writes, errors counts
        """
        total = self.stats['hits'] + self.stats['misses']
        hit_rate = (self.stats['hits'] / total * 100) if total > 0 else 0

        return {
            'hits': self.stats['hits'],
            'misses': self.stats['misses'],
            'writes': self.stats['writes'],
            'errors': self.stats['errors'],
            'total_requests': total,
            'hit_rate_percent': hit_rate
        }

    def print_stats(self):
        """Print cache statistics to stdout"""
        stats = self.get_stats()
        print("\n" + "=" * 50)
        print("Cache Statistics")
        print("=" * 50)
        print(f"Hits:              {stats['hits']}")
        print(f"Misses:            {stats['misses']}")
        print(f"Writes:            {stats['writes']}")
        print(f"Errors:            {stats['errors']}")
        print(f"Total Requests:    {stats['total_requests']}")
        print(f"Hit Rate:          {stats['hit_rate_percent']:.1f}%")
        print("=" * 50 + "\n")


if __name__ == '__main__':
    # Test caching functionality
    import tempfile
    import time
    from pathlib import Path

    print("=" * 60)
    print("Skill Cache Test Suite")
    print("=" * 60)

    # Create temporary test files
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        cache_dir = tmpdir / "cache"
        skill_file = tmpdir / "skill" / "SKILL.md"
        skill_file.parent.mkdir(parents=True)

        # Write test file
        skill_file.write_text("---\nname: test-skill\n---\nTest content")

        # Initialize cache
        cache = SkillMetadataCache(str(cache_dir))

        # Test 1: Cache miss on first access
        print("\n[Test 1] Initial cache miss")
        result = cache.get(skill_file)
        assert result is None, "First access should miss"
        assert cache.stats['misses'] == 1
        print("  ✅ Cache miss recorded")

        # Test 2: Cache write
        print("\n[Test 2] Cache write")
        test_metadata = {'name': 'test-skill', 'domain': 'test'}
        cache.set(skill_file, test_metadata)
        assert cache.stats['writes'] == 1
        print("  ✅ Cache write recorded")

        # Test 3: Cache hit
        print("\n[Test 3] Cache hit")
        result = cache.get(skill_file)
        assert result == test_metadata, "Should retrieve cached metadata"
        assert cache.stats['hits'] == 1
        print("  ✅ Cache hit recorded")

        # Test 4: Cache invalidation on file change
        print("\n[Test 4] Cache invalidation on file change")
        time.sleep(0.1)  # Ensure mtime changes
        skill_file.write_text("---\nname: test-skill-modified\n---\nModified content")
        result = cache.get(skill_file)
        assert result is None, "Should miss after file modification"
        assert cache.stats['misses'] == 2
        print("  ✅ Cache invalidation on mtime change")

        # Test 5: Manual invalidation
        print("\n[Test 5] Manual cache invalidation")
        cache.set(skill_file, test_metadata)
        cache.invalidate(skill_file)
        result = cache.get(skill_file)
        assert result is None, "Should miss after manual invalidation"
        print("  ✅ Manual invalidation works")

        # Test 6: Statistics
        print("\n[Test 6] Statistics tracking")
        cache.print_stats()
        stats = cache.get_stats()
        assert stats['total_requests'] > 0
        print("  ✅ Statistics collected")

    print("\n✅ All cache tests passed!")
