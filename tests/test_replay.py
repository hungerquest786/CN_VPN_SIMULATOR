import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from common.login import Sessions
from common.replay import ReplayWindow


def test_duplicate_rejected():
    w = ReplayWindow()
    assert w.accept(5)
    assert not w.accept(5)
    assert w.dropped == 1


def test_older_than_window_rejected():
    w = ReplayWindow()
    assert w.accept(0)
    assert w.accept(2000)            # window is now 977..2000
    assert not w.accept(100)         # far too old
    assert w.dropped == 1


def test_out_of_order_inside_window_accepted():
    w = ReplayWindow()
    for seq in (10, 12, 11, 5):      # 11 and 5 arrive late but are new and inside the window
        assert w.accept(seq)
    assert not w.accept(11)          # but a second copy is refused
    assert w.dropped == 1


def test_window_slides_forward():
    w = ReplayWindow()
    assert w.accept(0)
    assert w.accept(1023)            # 0 is still the oldest slot of the window
    assert not w.accept(0)           # seen already
    assert w.accept(1024)            # window moves: 0 falls out
    assert not w.accept(0)           # now rejected as too old, not as a duplicate
    assert w.accept(1000)            # still inside, never seen


def test_timeout_frees_address():
    s = Sessions()
    a = s.add("alice", 1, b"k", b"k")
    assert a.ip == "10.8.0.2"
    a.last_heard = 100.0
    assert s.expire(timeout=60, now=150.0) == []          # only 50 s quiet: stays
    assert [x.session_id for x in s.expire(timeout=60, now=161.0)] == [1]
    assert 1 not in s.by_id and "10.8.0.2" not in s.by_ip
    assert s.add("alice", 2, b"k", b"k").ip == "10.8.0.2"  # next login reuses the address


def test_drop_summary_is_rate_limited():
    from common.dropstats import DropStats
    d = DropStats()
    shown = [d.add("not IPv4", "x") for _ in range(100)]
    assert sum(x is not None for x in shown) == 5          # only the first few are printed
    assert d.summary(now=d.last_summary + 5) is None        # too soon
    assert "not IPv4=100" in d.summary(now=d.last_summary + 10)
    assert d.summary(now=d.last_summary + 100) is None      # nothing new to report
    d.add("wrong source")
    assert "wrong source=1" in d.summary(now=d.last_summary + 10)
