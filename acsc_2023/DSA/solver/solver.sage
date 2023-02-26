from sage.modules.free_module_integer import IntegerLattice
from Crypto.Util.number import *
from hashlib import sha256

# https://github.com/rkm0959/Inequality_Solving_with_CVP
def Babai_CVP(mat, target):
    M = IntegerLattice(mat, lll_reduce=True).reduced_basis
    G = M.gram_schmidt()[0]
    print(G.nrows())
    diff = target
    for i in reversed(range(G.nrows())):
        diff -=  M[i] * ((diff * G[i]) / (G[i] * G[i])).round()
    return target - diff
 
 
def solve(mat, lb, ub, weight = None):
    num_var  = mat.nrows()
    num_ineq = mat.ncols()
 
    max_element = 0 
    for i in range(num_var):
        for j in range(num_ineq):
            max_element = max(max_element, abs(mat[i, j]))
 
    if weight == None:
        weight = num_ineq * max_element
 
    if len(lb) != num_ineq:
        print("Fail: len(lb) != num_ineq")
        return
 
    if len(ub) != num_ineq:
        print("Fail: len(ub) != num_ineq")
        return
 
    for i in range(num_ineq):
        if lb[i] > ub[i]:
            print("Fail: lb[i] > ub[i] at index", i)
            return
 
    # scaling process begins
    max_diff = max([ub[i] - lb[i] for i in range(num_ineq)])
    applied_weights = []
 
    for i in range(num_ineq):
        ineq_weight = weight if lb[i] == ub[i] else max_diff // (ub[i] - lb[i])
        applied_weights.append(ineq_weight)
        for j in range(num_var):
            mat[j, i] *= ineq_weight
        lb[i] *= ineq_weight
        ub[i] *= ineq_weight
 
    # Solve CVP
    target = vector([(lb[i] + ub[i]) // 2 for i in range(num_ineq)])
    result = Babai_CVP(mat, target)
 
    for i in range(num_ineq):
        if (lb[i] <= result[i] <= ub[i]) == False:
            print("Fail : inequality does not hold after solving")
            break
 
    ## recover your result
    return result, applied_weights

def h(m: bytes) -> int:
    return int(sha256(m).hexdigest(), 16)

g = 4
p1, p2 = 6276170351477662358610296265757659534898563584329624403861678676207084984210281982964595245398676819568696602458985212398017251665201155991266054305219383699, 6592790035600261324619481304533463005761130886111654202136347967085156073379713687101783875841638513262245459729322943177912713281466956529743757383039213839
y1, y2 = 4402230695629594751098609664164747722309480897222957264699530671849221909102875035849237359507796750078710393158944361439911537205013148370997499859214033074, 1681962252704346790535503180583651281903938541944441796556533586799974913619493902209110690623728835694029912753819263510084101226503501626563053650880055759
m = b'omochi mochimochi mochimochi omochi'
r1, s1 = (2059408995750136677433298244389263055046695445249968690077607175900623237060138734944126780231327500254319039236115174790677322287273023749694890125234033630, 705204023016308665771881112578269844527040578525414513229064579516151996129198705744493237004425745778721444958494868745594673773644781132717640592278534802)
r2, s2 = (3246603518972133458487019157522113455602145970917894172952170087044203882577925192461339870709563972992589487629762432781841010769867505736764230484818447604, 2142497127325776381345617721109438439759390966544000203818908086062572965004742554536684765731611856029799528558073686810627789363181741779462572364133421373)
q1 = (p1 - 1)//2
q2 = (p2 - 1)//2
N = q1*q2
z1 = h(m) % q1
z2 = h(m) % q2
P.<x, y> = PolynomialRing(Zmod(N))

q1_part = z1 + r1*y - x*s1
q2_part = z2 + r2*y - x*s2
f = q1_part*inverse(q2,q1)*q2 + q2_part*inverse(q1,q2)*q1
coef = f.coefficients()

M = Matrix(ZZ,[
    [ 1, 0 , coef[0] ],
    [ 0, 1 , coef[1] ],
    [ 0, 0 , N] 
    ])

lb = [0 , 0 , int((coef[2]) % N)] 
ub = [2^512 , 2^512  , int((coef[2]) % N)] 

result, applied_weights = solve(M, lb, ub)

assert result[-1]% N == 0

print(long_to_bytes(-int(result[1])))