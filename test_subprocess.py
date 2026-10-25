import asyncio

async def test():
    proc = await asyncio.create_subprocess_exec(
        'cmd', '/c', 'echo', 'hello world',
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()
    print('exit:', proc.returncode, 'stdout:', stdout, 'stderr:', stderr)

asyncio.run(test())