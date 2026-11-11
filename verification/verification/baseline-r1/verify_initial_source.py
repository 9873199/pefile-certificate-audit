"""Read-only initial-commit replay to classify missing-corpus failures fairly."""
import json, os, subprocess, sys, tarfile, hashlib, time
import xml.etree.ElementTree as ET
from pathlib import Path
sys.path.insert(0, r'D:\hc\userFeedback\skill\user-feedback-workflow\scripts')
import workflow as w

b=Path(__file__).parent
plan=next(x for x in w.load(b/'plans.json') if x['uid']==122)
d=b/'evaluation'/plan['run_id']
f=w.load(d/'freeze.json')
v=d/'verification/baseline-r1'
v.mkdir(parents=True,exist_ok=False)
archive=v/'initial.tar'
subprocess.run(['git','archive','--format=tar','--output',str(archive),f['initial_sha']],cwd=d/'snapshot-repository',check=True)
source=v/'source';source.mkdir()
with tarfile.open(archive) as stream:
    for member in stream.getmembers():
        assert (source/member.name).resolve().is_relative_to(source.resolve())
    stream.extractall(source,filter='data')
env=os.environ.copy();env['PYTHONPATH']=str(source);env['PYTHONDONTWRITEBYTECODE']='1'
argv=[plan['python'],'-B','-m','pytest','-q','-p','no:cacheprovider',str(source/'tests'),
      '--basetemp',str(v/'tmp-regression'),'--junitxml',str(v/'baseline.xml'),'--disable-warnings']
start=time.monotonic()
with (v/'baseline.log').open('xb') as log:
    code=subprocess.run(argv,cwd=source,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=120).returncode
w.save(v/'baseline-command.json',{'argv':argv,'cwd':str(source),'PYTHONPATH':str(source),'exit_code':code,'seconds':round(time.monotonic()-start,2),'source_commit':f['initial_sha'],'initial_pefile_sha256':w.digest(source/'pefile.py'),'initial_archive_sha256':w.digest(archive),'purpose':'Initial source replay; not model final-artifact test score'})
root=ET.parse(v/'baseline.xml').getroot()
failures=[]
for item in root.iter('testcase'):
    fail=item.find('failure')
    if fail is not None:
        failures.append({'name':item.attrib['name'],'message':fail.attrib.get('message'),
                         'FileNotFoundError_in_trace':'FileNotFoundError' in (fail.text or ''),
                         'missing_corpus_path_in_trace':'pefile-tests' in (fail.text or '')})
final=w.load(d/'verification/regression-r1/test-results.json')['checks']['regression']
names=sorted(item['name'] for item in failures)
assert names==sorted(final['failure_cases'])
assert all(item['FileNotFoundError_in_trace'] and item['missing_corpus_path_in_trace'] for item in failures)
unchanged=[]
for file in (source/'tests').rglob('*.py'):
    relative=file.relative_to(source)
    assert w.digest(file)==w.digest(Path(f['artifact_directory'])/relative)
    unchanged.append(str(relative))
summary={'initial_commit':f['initial_sha'],'same_failure_names_as_frozen_final':True,
         'all_eleven_failures_missing_corpus':True,'failure_count':len(failures),
         'failures':failures,'original_test_files_unchanged':unchanged,
         'corpus_available':(source/'pefile-tests/tests').exists(),
         'not_a_full_corpus_pass':True}
w.save(v/'baseline-comparison.json',summary)
print(json.dumps(summary))
