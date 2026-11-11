"""Complete comparison of saved baseline output, disclosing checkout CRLF differences."""
import ast, json, subprocess, sys
from pathlib import Path
import xml.etree.ElementTree as ET
sys.path.insert(0,r'D:\hc\userFeedback\skill\user-feedback-workflow\scripts')
import workflow as w
b=Path(__file__).parent;d=b/'evaluation/uf-20261111-sec-08-pe-certificate-layout'
f=w.load(d/'freeze.json');v=d/'verification/baseline-r1';source=v/'source'
out=d/'verification/baseline-comparison-r2';out.mkdir(exist_ok=False)
files=[]
for file in (source/'tests').rglob('*.py'):
    relative=file.relative_to(source);frozen=Path(f['artifact_directory'])/relative
    old=file.read_bytes();new=frozen.read_bytes()
    assert old.replace(b'\r\n',b'\n')==new.replace(b'\r\n',b'\n'),str(relative)
    assert ast.dump(ast.parse(old))==ast.dump(ast.parse(new))
    files.append({'path':str(relative),'initial_archive_sha256':w.digest(file),'frozen_checkout_sha256':w.digest(frozen),
                  'raw_bytes_equal':old==new,'only_crlf_difference':old!=new,'python_ast_equal':True})
diff=subprocess.run(['git','diff','--name-status',f['initial_sha'],w.load(d/'snapshot-proof.json')['final_sha'],'--','tests'],
                    cwd=d/'snapshot-repository',capture_output=True,text=True,check=True).stdout
assert diff.strip()=='A\ttests/test_security_directory.py',diff
root=ET.parse(v/'baseline.xml').getroot();failed=[]
for case in root.iter('testcase'):
    failure=case.find('failure')
    if failure is not None:
        body=failure.text or ''
        failed.append({'name':case.attrib['name'],'message':failure.attrib.get('message'),
                       'FileNotFoundError_in_trace':'FileNotFoundError' in body,
                       'missing_corpus_path_in_trace':'pefile-tests' in body})
final=w.load(d/'verification/regression-r1/test-results.json')['checks']['regression']
assert sorted(x['name'] for x in failed)==sorted(final['failure_cases'])
assert len(failed)==11 and all(x['FileNotFoundError_in_trace'] and x['missing_corpus_path_in_trace'] for x in failed)
summary={'time':w.now(),'initial_commit':f['initial_sha'],'initial_test_command':'../baseline-r1/baseline-command.json',
         'same_eleven_failure_names_as_final':True,'all_eleven_failures_missing_corpus':True,'failures':failed,
         'initial_tests':files,'git_test_diff':diff,'source_comparison':'Raw hashes kept; CRLF-only checkout differences explicitly disclosed; AST equal. No original test edited in Git.',
         'initial_comparison_tool_issue':'baseline-r1 verifier asserted raw source byte equality; Git archive LF vs checkout CRLF caused that assertion after tests completed. Saved logs were reused without rerunning or modifying the model.',
         'corpus_available':False,'not_a_full_corpus_pass':True}
w.save(out/'baseline-comparison.json',summary)
(out/'classify_pe_baseline.py').write_bytes(Path(__file__).read_bytes())
print(json.dumps({'same_eleven_missing_corpus_failures':True,'original_tests_logically_unchanged':True,
                  'crlf_differences_disclosed':sum(x['only_crlf_difference'] for x in files)}))
