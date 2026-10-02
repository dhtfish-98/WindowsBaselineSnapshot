"""Compare all rows of frozen Windows policy lists to supplied observations."""
import csv
import io
import re
from importlib.resources import files as resources
from .common import InputError, Report, mapping, string

LIMITS=['Complete selected machine or user finding list; no live Windows collection, registry writes, remediation, unsigned code execution or fabricated observations.',
 'Methods label observation origin only; the collector and target OS/version/locale are not authenticated by this tool. Effective protection and collection accuracy remain OPEN.',
 'This new scope uses exact scalar or unordered semicolon-token comparisons. contains means exact token membership, not upstream substring behavior. Missing/not-configured/unavailable observations are OPEN; defaults never stand in for measured values.']

def load_policy(name):
    if name not in ('machine','user'):raise InputError('baseline must be machine or user')
    raw=resources(__package__).joinpath(name+'.csv').read_text(encoding='utf-8-sig')
    rows=list(csv.DictReader(io.StringIO(raw)));ids=set()
    for row in rows:
        if row['ID'] in ids:raise InputError('duplicate frozen policy ID')
        ids.add(row['ID'])
    return rows

def scalar(value,label):
    if type(value) is int and -(2**63)<=value<2**63:return str(value)
    if isinstance(value,str) and len(value)<=65536 and '\x00' not in value:return value
    raise InputError(label+' must be a bounded string or signed 64-bit integer')

def tokens(value):return tuple(sorted(p.strip().casefold() for p in re.split('[;,]',value) if p.strip()))

def integer(value):
    if len(value)>20 or not re.fullmatch(r'-?\d+',value):return None
    result=int(value)
    return result if -(2**63)<=result<2**63 else None

def compare(actual,expected,operator):
    if operator=='=':return tokens(actual)==tokens(expected)
    if operator=='!=':return tokens(actual)!=tokens(expected)
    if operator=='=|0':return not actual or tokens(actual)==tokens(expected)
    if operator in ('contains','notcontains'):
        wanted=tokens(expected);present=tokens(actual)
        result=bool(wanted) and all(token in present for token in wanted)
        return not result if operator=='notcontains' else result
    if operator in ('>=','<='):
        a,b=integer(actual.strip()),integer(expected.strip())
        if a is None or b is None:return None
        return a>=b if operator=='>=' else a<=b
    return None

def analyze(snapshot):
    mapping(snapshot,'snapshot');name=string(snapshot.get('baseline','machine'),'baseline');observations=mapping(snapshot.get('observations',{}),'observations')
    if len(observations)>10000:raise InputError('too many observations')
    report=Report('WindowsBaselineSnapshot','All rows in complete frozen '+name+' finding list against supplied measured values')
    rows=load_policy(name);valid={r['ID'] for r in rows}
    for id_,observation in observations.items():
        string(id_,'observation ID');mapping(observation,'observation')
        if id_ not in valid:report.add('unknown_observation','OPEN',id_,'Observation has no selected policy row')
    for row in rows:
        id_=row['ID'];entry=observations.get(id_)
        evidence=dict(id=id_,name=row['Name'],category=row['Category'],method=row['Method'],operator=row['Operator'],expected=row['RecommendedValue'],severity=row['Severity'])
        if entry is None:report.add('policy','OPEN',evidence,'No observation supplied');continue
        state=string(entry.get('state'),'observation.state')
        if state in ('not_configured','unavailable'):
            report.add('policy','OPEN',evidence,'No measured effective value: '+state);continue
        if state!='measured':raise InputError('unsupported observation.state')
        method=string(entry.get('method'),'observation.method')
        if method!=row['Method']:
            report.add('method','OPEN',evidence,'Observation source method mismatch');continue
        actual=scalar(entry.get('value'),'observation.value');evidence['actual']=actual
        result=compare(actual,row['RecommendedValue'],row['Operator'])
        if result is None:report.add('operator','OPEN',evidence,'Unsupported operator or non-numeric measurement')
        else:report.check('policy',result,evidence,'Measured value compared to complete frozen policy row')
    return report.finish(LIMITS)
