import unittest

from wshawk.daemon.state import GlobalState


class FakeTask:
    def __init__(self, *, done=False):
        self._done = done

    def done(self):
        return self._done


class GlobalStateTests(unittest.TestCase):
    def test_mutable_state_is_owned_by_each_instance(self):
        first = GlobalState()
        second = GlobalState()

        first.history.append({"id": "one"})
        first.active_scans["scan_task"] = FakeTask()
        first.scan_context["scan_id"] = "one"

        self.assertEqual(second.history, [])
        self.assertEqual(second.active_scans, {})
        self.assertEqual(second.scan_context, {})

    def test_active_task_slot_cannot_be_overwritten(self):
        state = GlobalState()
        task = FakeTask()
        state.register_task("blaster_task", task)

        with self.assertRaisesRegex(RuntimeError, "already active"):
            state.register_task("blaster_task", FakeTask())

        state.release_task("blaster_task", FakeTask())
        self.assertIs(state.active_scans["blaster_task"], task)
        state.release_task("blaster_task", task)
        self.assertFalse(state.task_running("blaster_task"))

    def test_completed_task_slot_can_be_replaced(self):
        state = GlobalState()
        state.register_task("scan_task", FakeTask(done=True))

        replacement = FakeTask()
        state.register_task("scan_task", replacement)

        self.assertIs(state.active_scans["scan_task"], replacement)


if __name__ == "__main__":
    unittest.main()
