import pytest
from core.crawler import Crawler
from core.session_manager import SessionManager
from core.scheduler import CrawlScheduler


@pytest.mark.asyncio
async def test_scheduler_add_and_visited():
    scheduler = CrawlScheduler(worker_count=2)
    await scheduler.add("http://test.com/page1", 0)
    await scheduler.add("http://test.com/page1", 0)  # doublon, ne doit pas être ajouté deux fois

    assert "http://test.com/page1" in scheduler.visited
    assert scheduler.queue.qsize() == 1


@pytest.mark.asyncio
async def test_scheduler_run_processes_all_items():
    scheduler = CrawlScheduler(worker_count=3)
    processed = []

    async def handler(url, depth):
        processed.append(url)

    await scheduler.add("http://test.com/a", 0)
    await scheduler.add("http://test.com/b", 0)
    await scheduler.add("http://test.com/c", 0)

    await scheduler.run(handler)

    assert len(processed) == 3
    assert "http://test.com/a" in processed


@pytest.mark.asyncio
async def test_session_manager_creates_session():
    manager = SessionManager(cookies={"test": "value"}, timeout=5)
    async with manager as session:
        assert session is not None
        assert session.closed is False
    assert session.closed is True


@pytest.mark.asyncio
async def test_crawler_run_on_invalid_target():
    """Le crawler ne doit pas planter si la cible est injoignable."""
    crawler = Crawler(base_url="http://this-domain-does-not-exist-12345.test", max_depth=1, concurrency=2)
    endpoints = await crawler.run()
    assert endpoints == []