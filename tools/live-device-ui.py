"""Inspect static UI labels without printing profile names, SSH logins or credentials."""
import json
import os
from pathlib import Path
import re
import subprocess
# Live target is supplied by the operator; nothing about it is stored in the repository.
HOST = os.environ['VELUM_LIVE_HOST']
PORT = os.environ['VELUM_LIVE_PORT']
import sys
from datetime import datetime, timezone
import xml.etree.ElementTree as ET

ADB = str(Path(os.environ['LOCALAPPDATA']) / 'Android/Sdk/platform-tools/adb.exe')
SERIAL = os.environ['ANDROID_SERIAL']
ROOT = Path(__file__).resolve().parents[1]

def adb(*args):
    return subprocess.run([ADB, '-s', SERIAL, *args], check=True, capture_output=True).stdout.decode('utf-8', 'strict')

APP_PACKAGE = 'com.velumtegra.xuimobile.next'

def read():
    adb('shell', 'uiautomator', 'dump', '/data/local/tmp/velum-preflight-ui.xml')
    return ET.fromstring(adb('shell', 'cat', '/data/local/tmp/velum-preflight-ui.xml'))

def require_velum_foreground(tree):
    """Stop before any input unless the whole dumped window belongs to VELUM."""
    packages = {n.get('package') for n in tree.iter('node') if n.get('package')}
    if packages != {APP_PACKAGE}:
        raise SystemExit('VELUM is not in the foreground; no input was sent')
    focus = adb('shell', 'dumpsys', 'window', 'displays')
    current = [line for line in focus.splitlines() if 'mCurrentFocus' in line]
    if not current or not all(APP_PACKAGE + '/' in line for line in current):
        raise SystemExit('VELUM window is not focused; no input was sent')

tree = read()
if len(sys.argv) > 1 and sys.argv[1] in ('top', 'down', 'ack', 'tap'):
    require_velum_foreground(tree)
labels = set()
for folder in ['app/src/main', 'feature/home/src/main']:
    for source in (ROOT / folder).rglob('*.kt'):
        labels.update(re.findall(r'"([^"\r\n]+)"', source.read_text(encoding='utf-8')))

if len(sys.argv) > 1 and sys.argv[1] in ('top', 'down'):
    bounds = tree.find('node').get('bounds')
    x1, y1, x2, y2 = map(int, re.fullmatch(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]', bounds).groups())
    for _ in range(2 if sys.argv[1] == 'top' else 1):
        start, end = (y1+(y2-y1)//3, y1+3*(y2-y1)//4)
        if sys.argv[1] == 'down':
            start, end = end, start
        adb('shell', 'input', 'swipe', str((x1+x2)//2), str(start), str((x1+x2)//2), str(end), '350')
    print('Scrolled')
elif len(sys.argv) > 1 and sys.argv[1] == 'ack':
    titles = {'Восстановить базу из копии?', 'Запустить восстановленную панель?'}
    assert any(n.get('text') in titles for n in tree.iter('node'))
    assert any(HOST in n.get('text', '') and PORT in n.get('text', '') for n in tree.iter('node'))
    checks = [n for n in tree.iter('node') if n.get('checkable') == 'true']
    assert len(checks) == 1 and checks[0].get('enabled') == 'true'
    if checks[0].get('checked') != 'true':
        x1, y1, x2, y2 = map(int, re.fullmatch(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]', checks[0].get('bounds')).groups())
        adb('shell', 'input', 'tap', str((x1+x2)//2), str((y1+y2)//2))
    print('Acknowledged the reviewed operation')
elif len(sys.argv) > 1 and sys.argv[1] == 'tap':
    label = {'new-preflight': 'Новая проверка установки', 'preflight': 'Проверить установку',
             'allow-preflight': 'Разрешить проверку', 'full-backup': 'Полная копия панели',
             'review-backup': 'Создать резервную копию', 'create-backup': 'Создать',
             'review-check': 'Проверить копию', 'check-backup': 'Проверить',
             'restore-open': 'Восстановить из этой копии', 'trial-review': 'Развернуть в пробную папку',
             'trial-deploy': 'Развернуть', 'trial-check': 'Проверить результат', 'refresh': 'Обновить',
             'management': 'Управление 3x-ui', 'management-entry': 'Управлять 3x-ui', 'backup-home': 'Резервная копия', 'archive': 'Копия от ',
             'compare-open': 'Дальше: сверить с панелью', 'compare': 'Сверить',
             'working-open': 'Дальше: восстановить базу', 'working-review': 'Восстановить базу',
             'working-confirm': 'Остановить и восстановить', 'start-open': 'Дальше: запустить панель',
             'start-review': 'Запустить панель', 'start-confirm': 'Запустить'}.get(sys.argv[2], sys.argv[2])
    allowed = {'Проверить установку', 'Новая проверка установки', 'Разрешить проверку',
               'Подробнее', 'Подробный состав копии', 'Закрыть', 'Полная копия панели',
               'Создать резервную копию', 'Создать', 'Проверить копию', 'Проверить',
               'Восстановить из этой копии', 'Развернуть в пробную папку', 'Развернуть', 'Проверить результат', 'Обновить',
               'Управление 3x-ui', 'Управлять 3x-ui', 'Резервное копирование', 'Резервная копия', 'Дальше: сверить с панелью', 'Сверить',
               'Дальше: восстановить базу', 'Восстановить базу', 'Остановить и восстановить',
               'Дальше: запустить панель', 'Запустить панель', 'Запустить', 'Копия от '}
    if label not in allowed:
        raise SystemExit('Only reviewed controls are supported')
    nodes = [n for n in tree.iter('node') if (n.get('text', '').startswith(label) if label == 'Копия от ' else n.get('text') == label) and n.get('enabled') == 'true']
    if len(nodes) != 1:
        raise SystemExit('Expected exactly one matching control')
    parents = {child: parent for parent in tree.iter() for child in parent}
    node = nodes[0]
    while node.get('clickable') != 'true':
        node = parents[node]
    assert node.get('enabled') == 'true', 'Control is disabled'
    x1, y1, x2, y2 = map(int, re.fullmatch(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]', node.get('bounds')).groups())
    if label in ('Создать', 'Развернуть', 'Остановить и восстановить', 'Запустить'):
        need_target = any(HOST in n.get('text', '') and PORT in n.get('text', '') for n in tree.iter('node'))
        titles = {'Создать': 'Создать резервную копию?', 'Развернуть': 'Развернуть копию в пробную папку?',
                  'Остановить и восстановить': 'Восстановить базу из копии?', 'Запустить': 'Запустить восстановленную панель?'}
        title = titles[label]
        need_dialog = any(n.get('text') == title for n in tree.iter('node'))
        if not (need_target and need_dialog):
            raise SystemExit('Exact backup review and authorized target must be visible')
        if label in ('Остановить и восстановить', 'Запустить'):
            assert any(n.get('checkable') == 'true' and n.get('checked') == 'true' for n in tree.iter('node'))
            expected_hash = json.loads((ROOT / 'build/live-backup-ui/independent-proof.json').read_text())['sha256']
            assert any(expected_hash[:16] in n.get('text', '') for n in tree.iter('node')), 'Archive binding is not visible'
        marker_names = {'Создать': 'create', 'Развернуть': 'trial', 'Остановить и восстановить': 'working-restore', 'Запустить': 'restored-start'}
        marker = ROOT / ('build/live-backup-ui/' + marker_names[label] + '-dispatched.json')
        marker.parent.mkdir(parents=True, exist_ok=True)
        with marker.open('x', encoding='utf-8') as output:
            json.dump({'target': HOST + ':' + PORT, 'at': datetime.now(timezone.utc).isoformat()}, output)
    adb('shell', 'input', 'tap', str((x1+x2)//2), str((y1+y2)//2))
    print(json.dumps({'tapped': label}, ensure_ascii=True))
else:
    found = []
    for node in tree.iter('node'):
        text = node.get('text', '')
        if text in labels and len(text) > 2:
            found.append({'text': text, 'bounds': node.get('bounds'), 'enabled': node.get('enabled')})
    print(json.dumps({'target_visible': any(HOST in n.get('text', '') and PORT in n.get('text', '') for n in tree.iter('node')),
        'labels': found}, ensure_ascii=True))
