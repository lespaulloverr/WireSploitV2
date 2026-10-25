import sys
import os
import tempfile
from pathlib import Path

# Set environment variable for test database before importing the app
# Create a temporary database file
temp_db = tempfile.NamedTemporaryFile(suffix='.sqlite3', delete=False)
temp_db.close()
os.environ['WIRESPOOL_DB'] = temp_db.name

sys.path.append(str(Path(__file__).parent.parent))

from engine import store
from engine import store

store.init()

from datetime import datetime, timezone, timedelta

def test_delete_old_investigations():
    # Create an investigation
    inv = store.create_investigation('Test Investigation for Expiry', srm=False)
    iid = inv['id']

    # Verify it exists
    assert store.get_investigation(iid) is not None

    # Set the updated_at to a date older than 3 days
    four_days_ago = datetime.now(timezone.utc) - timedelta(days=4)
    updated_at_str = four_days_ago.isoformat()

    # Update the investigation's updated_at directly in the database
    with store.connect() as c:
        c.execute('UPDATE investigations SET updated_at = ? WHERE id = ?', (updated_at_str, iid))

    # Call the cleanup function
    deleted_count = store.delete_old_investigations(days=3)

    # Verify that the investigation was deleted
    assert store.get_investigation(iid) is None
    # We expect at least one deletion
    assert deleted_count >= 1

# Clean up the temporary database file after the test
import atexit
atexit.register(lambda: os.unlink(temp_db.name))

if __name__ == '__main__':
    test_delete_old_investigations()
    print('All expiry tests passed')