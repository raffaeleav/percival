from functools import partial
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor


def io_parallelize(function, items, **kwargs): 
    task = partial(function, **kwargs) if kwargs else function
    
    with ThreadPoolExecutor() as executor:
        items = executor.map(task, items)

    results = []
    
    for item in items:
        if item is not None:
            results.append(item)

    return results


def cpu_parallelize(function, items, **kwargs):
    task = partial(function, **kwargs) if kwargs else function

    with ProcessPoolExecutor() as executor:
        items = executor.map(task, items)

    results = []
    
    for item in items:
        if item is not None:
            results.append(item)

    return results
