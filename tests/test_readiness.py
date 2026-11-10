import unittest
from pathlib import Path
from acac.readiness import checklist_status


class ReadinessTests(unittest.TestCase):
    def test_checklist_is_not_falsely_marked_complete(self):
        status = checklist_status(Path(__file__).parents[1] / "docs" / "v1_implementation_checklist.md")
        self.assertGreater(status["unchecked"], 0)


if __name__ == "__main__": unittest.main()
