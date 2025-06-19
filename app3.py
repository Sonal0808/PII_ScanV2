import streamlit as st
import fitz  # PyMuPDF
import tempfile
import os
import re
from docx import Document
from io import BytesIO
from email import policy
from email.parser import BytesParser
import extract_msg
import pandas as pd
import xml.etree.ElementTree as ET
from PIL import Image, ImageDraw
import pytesseract

# ------------------------------
# PII regex patterns (common structured info)
PII_PATTERNS = {
    "Email": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "Phone": r"\+?\d[\d\s\-()]{8,}\d",
    "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
    "Credit Card": r"\b(?:\d[ -]*?){13,16}\b",
    "DOB": r"\b(?:0?[1-9]|[12][0-9]|3[01])[- /.](?:0?[1-9]|1[012])[- /.](?:19|20)?\d{2}\b",
    "ZIP Code": r"\b\d{5}(-\d{4})?\b",
    "Driver License": r"\b[A-Z]{1,2}\d{4,9}\b",
    "Passport": r"\b[A-PR-WYa-pr-wy][1-9]\d\s?\d{4}[1-9]\b",
}

# Heuristic name detection
def find_names(text):
    return re.findall(r"\b([A-Z][a-z]+(?: [A-Z][a-z]+)+)\b", text)

# Keyword-based patterns
KEYWORD_PII = {
    "Gender": [r"\b(Male|Female|Other|Man|Woman|Non-binary|Transgender)\b"],
    "Race": [r"\b(Asian|Black|White|Hispanic|Latino|Native American|Caucasian)\b"],
    "Religion": [r"\b(Christian|Muslim|Jewish|Hindu|Buddhist|Atheist|Agnostic)\b"],
    "Medical": [r"\b(Diabetes|Cancer|HIV|AIDS|Asthma|Depression|Blood Pressure)\b"],
    "Place of Birth": [r"\b(New York|London|Paris|Delhi|Tokyo|Sydney|Toronto)\b"],
}

# ------------------------------
# PII Redaction for PDFs
def redact_pdf(input_path):
    doc = fitz.open(input_path)
    for page in doc:
        text = page.get_text("text")
        names = find_names(text)
        all_pii = []
        for label, pattern in PII_PATTERNS.items():
            all_pii.extend([(label, m.group()) for m in re.finditer(pattern, text)])
        for label, patterns in KEYWORD_PII.items():
            for p in patterns:
                all_pii.extend([(label, m.group()) for m in re.finditer(p, text, flags=re.IGNORECASE)])
        for name in names:
            all_pii.append(("Full Name", name))

        for label, pii_text in all_pii:
            areas = page.search_for(pii_text)
            for area in areas:
                page.add_redact_annot(area, fill=(0, 0, 0))

        page.apply_redactions()

    out_path = input_path.replace(".pdf", "_redacted.pdf")
    doc.save(out_path)
    doc.close()
    return out_path

# ------------------------------
def redact_text(text):
    names = find_names(text)
    for label, pattern in PII_PATTERNS.items():
        text = re.sub(pattern, f"[REDACTED {label}]", text)
    for label, patterns in KEYWORD_PII.items():
        for p in patterns:
            text = re.sub(p, f"[REDACTED {label}]", text, flags=re.IGNORECASE)
    for name in names:
        text = text.replace(name, "[REDACTED Full Name]")
    return text

# ------------------------------
def redact_docx(file_bytes):
    doc = Document(BytesIO(file_bytes))
    for para in doc.paragraphs:
        para.text = redact_text(para.text)
    out_stream = BytesIO()
    doc.save(out_stream)
    return out_stream.getvalue()

# ------------------------------
def redact_eml(file_bytes):
    msg = BytesParser(policy=policy.default).parsebytes(file_bytes)
    subject = msg['subject'] or ""
    redacted_subject = redact_text(subject)
    if 'subject' in msg:
        msg.replace_header('subject', redacted_subject)
    else:
        msg['subject'] = redacted_subject
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == 'text/plain':
                body = part.get_content()
                part.set_content(redact_text(body))
    else:
        body = msg.get_content()
        msg.set_content(redact_text(body))
    return msg.as_bytes()

# ------------------------------
def redact_msg_file(file_path):
    msg = extract_msg.Message(file_path)
    redacted_body = redact_text(msg.body or "")
    redacted_subject = redact_text(msg.subject or "")
    combined = f"Subject: {redacted_subject}\n\n{redacted_body}"
    return combined.encode('utf-8')

# ------------------------------
def redact_excel(file_path):
    df = pd.read_excel(file_path, dtype=str)
    for col in df.columns:
        df[col] = df[col].astype(str).apply(redact_text)
    out_stream = BytesIO()
    with pd.ExcelWriter(out_stream, engine='openpyxl') as writer:
        df.to_excel(writer, index=False)
    return out_stream.getvalue()

# ------------------------------
def redact_xml(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()
    def redact_element(element):
        if element.text:
            element.text = redact_text(element.text)
        for child in element:
            redact_element(child)
    redact_element(root)
    out_stream = BytesIO()
    tree.write(out_stream, encoding='utf-8', xml_declaration=True)
    return out_stream.getvalue()

# ------------------------------
# New: PII Redaction on Images
def redact_image(input_path):
    img = Image.open(input_path).convert("RGB")
    draw = ImageDraw.Draw(img)

    # Use pytesseract to extract detailed OCR data with bounding boxes
    data = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT)

    n_boxes = len(data['level'])
    for i in range(n_boxes):
        text = data['text'][i]
        if not text.strip():
            continue

        # Check for PII matches on this text segment
        pii_found = False
        for label, pattern in PII_PATTERNS.items():
            if re.fullmatch(pattern, text):
                pii_found = True
                break
        if not pii_found:
            for label, patterns in KEYWORD_PII.items():
                for p in patterns:
                    if re.fullmatch(p, text, flags=re.IGNORECASE):
                        pii_found = True
                        break
                if pii_found:
                    break

        # Also check for names heuristically (allow partial matches)
        if not pii_found:
            # if text matches part of a name pattern
            if re.fullmatch(r"[A-Z][a-z]+(?: [A-Z][a-z]+)*", text):
                pii_found = True

        # If PII found, redact the bounding box area
        if pii_found:
            (x, y, w, h) = (data['left'][i], data['top'][i], data['width'][i], data['height'][i])
            draw.rectangle([(x, y), (x + w, y + h)], fill="black")

    return img

# ------------------------------
# Streamlit UI
st.title("PII Scan")

st.write("""
Upload files to scan and redact Personally Identifiable Information (PII) from various formats (PDF, DOCX, EML, TXT, XML, Excel, Images, etc.).
""")

uploaded_file = st.file_uploader(
    "Upload your file",
    type=["pdf", "txt", "docx", "eml", "msg", "xls", "xlsx", "xml", "png", "jpg", "jpeg", "gif"]
)

if uploaded_file:
    file_details = {"filename": uploaded_file.name, "filetype": uploaded_file.type}
    ext = file_details["filename"].split(".")[-1].lower()
    st.write(f"📄 File uploaded: {file_details['filename']}")

    with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(uploaded_file.name)[1]) as tmp_file:
        tmp_file.write(uploaded_file.read())
        tmp_path = tmp_file.name

    if ext in ["png", "jpg", "jpeg", "gif"]:
        st.info("🖼️ Processing Image File...")
        try:
            redacted_img = redact_image(tmp_path)
            st.image(redacted_img, caption="Redacted Image", use_container_width=True)
            st.success("✅ Image redacted!")
            # Provide download of redacted image
            img_byte_arr = BytesIO()
            redacted_img.save(img_byte_arr, format='PNG')
            st.download_button("Download redacted Image", img_byte_arr.getvalue(), file_name="redacted_" + file_details["filename"])
        except Exception as e:
            st.error(f"Error processing image: {e}")

    elif ext == "pdf":
        st.info("Processing PDF...")
        output_path = redact_pdf(tmp_path)
        with open(output_path, "rb") as f:
            redacted_pdf_bytes = f.read()
        st.success("✅ PDF redacted!")
        st.download_button("Download redacted PDF", redacted_pdf_bytes, file_name="redacted_" + file_details["filename"])

    elif ext == "docx":
        st.info("Processing DOCX...")
        with open(tmp_path, "rb") as f:
            file_bytes = f.read()
        redacted_bytes = redact_docx(file_bytes)
        st.success("✅ DOCX redacted!")
        st.download_button("Download redacted DOCX", redacted_bytes, file_name="redacted_" + file_details["filename"])

    elif ext == "eml":
        st.info("Processing EML...")
        with open(tmp_path, "rb") as f:
            file_bytes = f.read()
        redacted_bytes = redact_eml(file_bytes)
        st.success("✅ EML redacted!")
        st.download_button("Download redacted EML", redacted_bytes, file_name="redacted_" + file_details["filename"])

    elif ext == "msg":
        st.info("Processing MSG...")
        try:
            redacted_bytes = redact_msg_file(tmp_path)
            st.success("✅ MSG redacted!")
            st.download_button("Download redacted MSG content (txt)", redacted_bytes, file_name="redacted_" + file_details["filename"].replace(".msg", ".txt"))
        except Exception as e:
            st.error(f"Error processing MSG: {e}")

    elif ext in ["xls", "xlsx"]:
        st.info("Processing Excel...")
        try:
            redacted_bytes = redact_excel(tmp_path)
            st.success("✅ Excel redacted!")
            st.download_button("Download redacted Excel", redacted_bytes, file_name="redacted_" + file_details["filename"])
        except Exception as e:
            st.error(f"Error processing Excel: {e}")

    elif ext == "xml":
        st.info("Processing XML...")
        try:
            redacted_bytes = redact_xml(tmp_path)
            st.success("✅ XML redacted!")
            st.download_button("Download redacted XML", redacted_bytes, file_name="redacted_" + file_details["filename"])
        except Exception as e:
            st.error(f"Error processing XML: {e}")

    elif ext == "txt":
        st.info("Processing TXT...")
        with open(tmp_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        redacted_content = redact_text(content)
        st.text_area("Redacted Text", redacted_content, height=300)
        st.download_button("Download redacted TXT", redacted_content.encode("utf-8"), file_name="redacted_" + file_details["filename"])

    else:
        st.warning("Unsupported file type or no redaction available.")