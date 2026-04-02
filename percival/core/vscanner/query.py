from vdb.lib import config, db6 as db_lib
from vdb.lib.orasclient import download_image

def download_db():
    db_url = config.VDB_DATABASE_URL
    
    download_image(db_url, config.DATA_DIR)

def is_updated():
    return db_lib.needs_update(days=1)

def init_db():
    if not is_updated():
        download_db()