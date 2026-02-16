' ============================================================
' SECURITY ASSESSMENT TOOL v3 - COMPLETE BUILDER + MACROS
' ============================================================
' Creates the ENTIRE tool from a blank workbook.
'
' HOW TO USE:
' 1. Open a brand new blank Excel workbook
' 2. Press Alt+F11 to open the VBA Editor
' 3. Click Insert > Module
' 4. Paste ALL of this code
' 5. Press F5 and select "BuildSecurityTool"
' 6. Wait ~60 seconds for the tool to build
' 7. Save as .xlsm to keep macros
'
' INCLUDED MACROS:
'   BuildSecurityTool    - Creates entire tool from scratch
'   RefreshChecklist     - Filters to show only applicable controls
'   ShowAllControls      - Clears all filters
'   ExportSummary        - Generates 1-page executive summary
'   AddControlFromConsole - Adds new control from Admin Console
'   UnlockForAdmin       - Prompts password, unlocks all sheets
'   LockAllSheets        - Re-locks all sheets
'   LogChange            - Writes audit entry to Change Log
' ============================================================

Const ADMIN_PWD As String = "Admin123"

' ============================================================
' MAIN BUILDER
' ============================================================
Sub BuildSecurityTool()
    Application.ScreenUpdating = False
    Application.Calculation = xlCalculationManual
    Application.DisplayAlerts = False
    
    Dim wb As Workbook: Set wb = ActiveWorkbook
    
    ' Delete all sheets except first
    Do While wb.Sheets.Count > 1
        wb.Sheets(wb.Sheets.Count).Delete
    Loop
    
    ' Create sheets
    wb.Sheets(1).Name = "Instructions"
    Dim sn As Variant
    sn = Array("Project Profile", "Controls Library", "Security Checklist", "Dashboard", "Admin Console", "Change Log", "Lookups")
    Dim i As Long
    For i = 0 To UBound(sn)
        wb.Sheets.Add After:=wb.Sheets(wb.Sheets.Count)
        wb.Sheets(wb.Sheets.Count).Name = sn(i)
    Next i
    
    ' Tab colors
    wb.Sheets("Instructions").Tab.Color = RGB(27, 42, 74)
    wb.Sheets("Project Profile").Tab.Color = RGB(68, 114, 196)
    wb.Sheets("Controls Library").Tab.Color = RGB(46, 125, 50)
    wb.Sheets("Security Checklist").Tab.Color = RGB(198, 40, 40)
    wb.Sheets("Dashboard").Tab.Color = RGB(255, 111, 0)
    wb.Sheets("Admin Console").Tab.Color = RGB(74, 20, 140)
    wb.Sheets("Change Log").Tab.Color = RGB(55, 71, 79)
    wb.Sheets("Lookups").Tab.Color = RGB(217, 217, 217)
    
    ' Build all sheets
    Call BuildLookups(wb)
    Call BuildProfile(wb)
    Call BuildControlsLibrary(wb)
    Call BuildChecklist(wb)
    Call BuildDashboard(wb)
    Call BuildAdminConsole(wb)
    Call BuildChangeLog(wb)
    Call BuildInstructions(wb)
    
    ' Protect all sheets
    Call LockAllSheets
    
    ' Hide change log
    wb.Sheets("Change Log").Visible = xlSheetHidden
    
    wb.Sheets("Instructions").Activate
    Application.Calculation = xlCalculationAutomatic
    Application.ScreenUpdating = True
    Application.DisplayAlerts = True
    
    MsgBox "Security Controls Assessment Tool v3 built!" & vbCrLf & vbCrLf & _
           "8 sheets, 124 controls (107 base + 17 SaaS)." & vbCrLf & _
           "Admin password: " & ADMIN_PWD & vbCrLf & vbCrLf & _
           "Start: Fill in 'Project Profile' then run 'RefreshChecklist'.", vbInformation, "Build Complete"
End Sub

' ============================================================
' HELPER FORMATTING SUBS
' ============================================================
Sub FmtHeader(rng As Range)
    With rng
        .Font.Name = "Arial": .Font.Size = 11: .Font.Bold = True: .Font.Color = RGB(255, 255, 255)
        .Interior.Color = RGB(27, 42, 74)
        .HorizontalAlignment = xlCenter: .VerticalAlignment = xlCenter: .WrapText = True
        .Borders.LineStyle = xlContinuous: .Borders.Color = RGB(191, 191, 191)
    End With
End Sub

Sub FmtSection(ws As Worksheet, r As Long, txt As String)
    ws.Range(ws.Cells(r, 3), ws.Cells(r, 5)).Merge
    With ws.Cells(r, 3)
        .Value = txt: .Font.Name = "Arial": .Font.Size = 11: .Font.Bold = True
        .Font.Color = RGB(255, 255, 255): .Interior.Color = RGB(46, 80, 144)
        .HorizontalAlignment = xlLeft: .VerticalAlignment = xlCenter
    End With
    ws.Cells(r, 4).Interior.Color = RGB(46, 80, 144)
    ws.Cells(r, 5).Interior.Color = RGB(46, 80, 144)
End Sub

Sub AddPRow(ws As Worksheet, r As Long, lbl As String, hint As String, Optional dvList As String = "")
    With ws.Cells(r, 3)
        .Value = lbl: .Font.Name = "Arial": .Font.Size = 10: .Font.Bold = True
        .Borders.LineStyle = xlContinuous: .Locked = True
    End With
    With ws.Cells(r, 4)
        .Interior.Color = RGB(255, 242, 204): .Borders.LineStyle = xlContinuous
        .Font.Name = "Arial": .Font.Size = 10: .Locked = False
    End With
    If dvList <> "" Then
        With ws.Cells(r, 4).Validation
            .Delete
            .Add Type:=xlValidateList, AlertStyle:=xlValidAlertStop, Formula1:=dvList
            .ErrorMessage = "Please select from the dropdown list"
        End With
    End If
    With ws.Cells(r, 5)
        .Value = hint: .Font.Name = "Arial": .Font.Size = 9: .Font.Italic = True
        .Font.Color = RGB(128, 128, 128): .Locked = True
    End With
End Sub

' ============================================================
' LOOKUPS
' ============================================================
Sub BuildLookups(wb As Workbook)
    Dim ws As Worksheet: Set ws = wb.Sheets("Lookups")
    Dim h As Variant, col As Long
    h = Array("DeploymentModel", "AppTier", "DataClassification", "YesNo", "Priority", "Status", "RiskLevel", "AuthMethod", "Compliance", "NetworkZone", _
        "Component", _
        "DataType", _
        "Enabled")
    For col = 1 To 13: ws.Cells(1, col).Value = h(col - 1): ws.Columns(col).ColumnWidth = 20: Next col
    Call FmtHeader(ws.Range("A1:M1"))
    ws.Range("A2:A6").Value = Application.Transpose(Array("IaaS", "PaaS", "SaaS", "On-Premises", "Hybrid"))
    ws.Range("B2:B7").Value = Application.Transpose(Array("3-Tier", "Microservices", "Serverless", "Monolithic", "N-Tier", "Event-Driven"))
    ws.Range("C2:C5").Value = Application.Transpose(Array("Public", "Restricted", "Confidential", "Secret"))
    ws.Range("D2:D3").Value = Application.Transpose(Array("Yes", "No"))
    ws.Range("E2:E4").Value = Application.Transpose(Array("MUST-HAVE", "SHOULD-HAVE", "NICE-TO-HAVE"))
    ws.Range("F2:F5").Value = Application.Transpose(Array("Not Started", "In Progress", "Implemented", "N/A"))
    ws.Range("G2:G4").Value = Application.Transpose(Array("High", "Medium", "Low"))
    ws.Range("H2:H8").Value = Application.Transpose(Array("SSO", "MFA", "LDAP", "OAuth", "SAML", "Local Auth", "Certificate-Based"))
    ws.Range("I2:I8").Value = Application.Transpose(Array("GDPR", "HIPAA", "PCI-DSS", "SOX", "ISO 27001", "NIST", "None"))
    ws.Range("J2:J6").Value = Application.Transpose(Array("DMZ", "Internal", "External", "Restricted", "Management"))
    ws.Range("K2:K9").Value = Application.Transpose(Array("Web Application", "Application Server", "Database", "API Gateway", "Message Queue", _
        "Load Balancer", _
        "File Storage", _
        "Cache Server"))
    ws.Range("L2:L8").Value = Application.Transpose(Array("PII", "Payment Data", "Health Records", "Financial Data", "Intellectual Property", _
        "General Business", _
        "Public Data"))
    ws.Range("M2:M3").Value = Application.Transpose(Array("Yes", "No"))
    ws.Range("A2:M12").Font.Name = "Arial": ws.Range("A2:M12").Font.Size = 10
    ws.Range("A2:M12").Borders.LineStyle = xlContinuous
End Sub

' ============================================================
' PROJECT PROFILE
' ============================================================
Sub BuildProfile(wb As Workbook)
    Dim ws As Worksheet: Set ws = wb.Sheets("Project Profile")
    ws.Columns("A").ColumnWidth = 3: ws.Columns("B").ColumnWidth = 5
    ws.Columns("C").ColumnWidth = 35: ws.Columns("D").ColumnWidth = 40
    ws.Columns("E").ColumnWidth = 40: ws.Columns("F").ColumnWidth = 15
    
    ws.Range("C2:E2").Merge
    ws.Cells(2, 3).Value = "PROJECT SECURITY PROFILE"
    ws.Cells(2, 3).Font.Name = "Arial": ws.Cells(2, 3).Font.Size = 16
    ws.Cells(2, 3).Font.Bold = True: ws.Cells(2, 3).Font.Color = RGB(27, 42, 74)
    ws.Range("C3:E3").Merge
    ws.Cells(3, 3).Value = "Complete all yellow-highlighted fields using dropdowns"
    ws.Cells(3, 3).Font.Name = "Arial": ws.Cells(3, 3).Font.Size = 10
    ws.Cells(3, 3).Font.Italic = True: ws.Cells(3, 3).Font.Color = RGB(46, 80, 144)
    
    Dim r As Long
    r = 5: Call FmtSection(ws, r, "SECTION 1: PROJECT INFORMATION"): r = 6
    Call AddPRow(ws, r, "Project Name", "Enter the official project name"): r = r + 1
    Call AddPRow(ws, r, "Project ID / Reference", "Unique identifier"): r = r + 1
    Call AddPRow(ws, r, "Project Owner", "Name of the system/project owner"): r = r + 1
    Call AddPRow(ws, r, "Assessment Date", "Date of this assessment"): r = r + 1
    Call AddPRow(ws, r, "Business Unit", "Department or business unit"): r = r + 1
    
    r = r + 1: Call FmtSection(ws, r, "SECTION 2: ARCHITECTURE & DEPLOYMENT"): r = r + 1
    Call AddPRow(ws, r, "Deployment Model", "IaaS / PaaS / SaaS / On-Prem / Hybrid", "=Lookups!$A$2:$A$6"): r = r + 1
    Call AddPRow(ws, r, "Application Architecture", "3-Tier, Microservices, etc.", "=Lookups!$B$2:$B$7"): r = r + 1
    Call AddPRow(ws, r, "Risk Classification", "Overall project risk level", "=Lookups!$G$2:$G$4"): r = r + 1
    Call AddPRow(ws, r, "Business Criticality", "How critical to business ops?", "=Lookups!$G$2:$G$4"): r = r + 1
    
    r = r + 1: Call FmtSection(ws, r, "SECTION 3: COMPONENTS PRESENT (Select Yes/No)"): r = r + 1
    Dim comps As Variant
    comps = Array("Web Application", "Application Server", "Database", "API Gateway / APIs", "Message Queue", "Load Balancer", _
        "File Storage / Object Storage", _
        "Cache Server (Redis/Memcached)", "Containerised Workloads (Docker/K8s)", "Serverless Functions")
    Dim ci As Long
    For ci = 0 To UBound(comps): Call AddPRow(ws, r, CStr(comps(ci)), "Select Yes or No", "=Lookups!$D$2:$D$3"): r = r + 1: Next ci
    
    r = r + 1: Call FmtSection(ws, r, "SECTION 4: DATA CLASSIFICATION & ACCESS"): r = r + 1
    Call AddPRow(ws, r, "Highest Data Classification", "Public / Restricted / Confidential / Secret", "=Lookups!$C$2:$C$5"): r = r + 1
    Call AddPRow(ws, r, "Contains PII?", "Personal Identifiable Information", "=Lookups!$D$2:$D$3"): r = r + 1
    Call AddPRow(ws, r, "Contains Payment Data?", "Credit card, bank account, etc.", "=Lookups!$D$2:$D$3"): r = r + 1
    Call AddPRow(ws, r, "Contains Health Records?", "Medical or health-related data", "=Lookups!$D$2:$D$3"): r = r + 1
    Call AddPRow(ws, r, "Contains Financial Data?", "Financial statements, transactions", "=Lookups!$D$2:$D$3"): r = r + 1
    Call AddPRow(ws, r, "Primary Authentication Method", "How users authenticate", "=Lookups!$H$2:$H$8"): r = r + 1
    Call AddPRow(ws, r, "MFA Enabled?", "Multi-Factor Authentication in use?", "=Lookups!$D$2:$D$3"): r = r + 1
    Call AddPRow(ws, r, "Privileged Accounts Required?", "Admin/root-level access needed?", "=Lookups!$D$2:$D$3"): r = r + 1
    Call AddPRow(ws, r, "Number of Privileged Accounts", "Approximate count"): r = r + 1
    
    r = r + 1: Call FmtSection(ws, r, "SECTION 5: CONNECTIVITY & INTEGRATION"): r = r + 1
    Call AddPRow(ws, r, "Internet-Facing?", "Accessible from the public internet?", "=Lookups!$D$2:$D$3"): r = r + 1
    Call AddPRow(ws, r, "External API Integrations?", "Connects to external 3rd-party APIs?", "=Lookups!$D$2:$D$3"): r = r + 1
    Call AddPRow(ws, r, "Third-Party Service Integrations?", "Uses external SaaS/services?", "=Lookups!$D$2:$D$3"): r = r + 1
    Call AddPRow(ws, r, "Remote Access Required?", "Users access remotely (VPN, etc.)?", "=Lookups!$D$2:$D$3"): r = r + 1
    Call AddPRow(ws, r, "File Transfer Required?", "System sends/receives files?", "=Lookups!$D$2:$D$3"): r = r + 1
    Call AddPRow(ws, r, "Primary Network Zone", "DMZ / Internal / External / Restricted", "=Lookups!$J$2:$J$6"): r = r + 1
    
    r = r + 1: Call FmtSection(ws, r, "SECTION 6: COMPLIANCE & REGULATORY"): r = r + 1
    Call AddPRow(ws, r, "GDPR Applicable?", "EU General Data Protection Regulation", "=Lookups!$D$2:$D$3"): r = r + 1
    Call AddPRow(ws, r, "PCI-DSS Applicable?", "Payment Card Industry standard", "=Lookups!$D$2:$D$3"): r = r + 1
    Call AddPRow(ws, r, "HIPAA Applicable?", "Health Insurance Portability Act", "=Lookups!$D$2:$D$3"): r = r + 1
    Call AddPRow(ws, r, "SOX Applicable?", "Sarbanes-Oxley Act", "=Lookups!$D$2:$D$3"): r = r + 1
    Call AddPRow(ws, r, "ISO 27001 Applicable?", "Information Security Management", "=Lookups!$D$2:$D$3"): r = r + 1
End Sub
' ============================================================
' CONTROLS LIBRARY (124 controls: 107 base + 17 SaaS)
' ============================================================
Sub BuildControlsLibrary(wb As Workbook)
    Dim ws As Worksheet: Set ws = wb.Sheets("Controls Library")
    Dim hdrs As Variant
    hdrs = Array("Control ID", "Domain", "Sub-Domain", "Control Description", "Implementation Guidance", "Verification Method", "Applicable Components", _
        "Trigger Condition", _
        "Base Priority", "Source Reference", "Enabled")
    Dim widths As Variant
    widths = Array(12, 18, 22, 50, 45, 35, 25, 35, 14, 20, 10)
    Dim j As Long
    For j = 0 To 10
        ws.Cells(1, j + 1).Value = hdrs(j): ws.Columns(j + 1).ColumnWidth = widths(j)
    Next j
    Call FmtHeader(ws.Range("A1:K1"))
    ws.Cells(1, 11).Interior.Color = RGB(255, 111, 0)
    
    ' Load all 124 controls via helper
    Dim n As Long: n = 0
    Call LoadBaseControls(ws, n)
    Call LoadSaaSControls(ws, n)
    
    ' Format
    Dim r As Long
    For r = 2 To n + 1
        ws.Range(ws.Cells(r, 1), ws.Cells(r, 11)).Font.Name = "Arial"
        ws.Range(ws.Cells(r, 1), ws.Cells(r, 11)).Font.Size = 10
        ws.Range(ws.Cells(r, 1), ws.Cells(r, 11)).WrapText = True
        ws.Range(ws.Cells(r, 1), ws.Cells(r, 11)).VerticalAlignment = xlTop
        ws.Range(ws.Cells(r, 1), ws.Cells(r, 11)).Borders.LineStyle = xlContinuous
        ws.Range(ws.Cells(r, 1), ws.Cells(r, 11)).Borders.Color = RGB(191, 191, 191)
        ws.Cells(r, 11).HorizontalAlignment = xlCenter
        If r Mod 2 = 0 Then ws.Range(ws.Cells(r, 1), ws.Cells(r, 11)).Interior.Color = RGB(242, 242, 242)
    Next r
    
    ' Enabled dropdown
    With ws.Range("K2:K" & n + 1).Validation
        .Delete
        .Add Type:=xlValidateList, AlertStyle:=xlValidAlertStop, Formula1:="=Lookups!$M$2:$M$3"
    End With
    
    ' Conditional format Enabled=No
    ws.Range("K2:K" & n + 1).FormatConditions.Add Type:=xlCellValue, Operator:=xlEqual, Formula1:="=""No"""
    ws.Range("K2:K" & n + 1).FormatConditions(1).Interior.Color = RGB(217, 217, 217)
    ws.Range("K2:K" & n + 1).FormatConditions(1).Font.Color = RGB(153, 153, 153)
    
    On Error Resume Next
    ws.Activate
    ws.Range("A2").Select
    ActiveWindow.FreezePanes = True
    On Error GoTo 0
End Sub

Sub WriteCtrl(ws As Worksheet, n As Long, id As String, dom As String, sub_ As String, desc As String, guide As String, verify As String, comp As String, _
    trig As String, _
    pri As String, src As String)
    n = n + 1
    ws.Cells(n + 1, 1).Value = id: ws.Cells(n + 1, 2).Value = dom: ws.Cells(n + 1, 3).Value = sub_
    ws.Cells(n + 1, 4).Value = desc: ws.Cells(n + 1, 5).Value = guide: ws.Cells(n + 1, 6).Value = verify
    ws.Cells(n + 1, 7).Value = comp: ws.Cells(n + 1, 8).Value = trig: ws.Cells(n + 1, 9).Value = pri
    ws.Cells(n + 1, 10).Value = src: ws.Cells(n + 1, 11).Value = "Yes"
End Sub

Sub LoadBaseControls(ws As Worksheet, n As Long)
    ' Info Classification
    Call WriteCtrl(ws, n, "IC-001", "Info Classification", "Asset Ownership", _
        "All information assets must have a designated owner responsible for classification and access control", _
        "Assign owner for every system/data asset; document in asset register", "Review asset register for completeness", "All", "ALWAYS", "MUST-HAVE", _
            "Std 2.2.1")
    Call WriteCtrl(ws, n, "IC-002", "Info Classification", "Data Labelling", "All information assets shall be labelled with their classification level", _
        "Apply classification labels to all data stores and documents", "Audit sample of assets for correct labels", "All", "ALWAYS", "MUST-HAVE", _
            "Std 2.2.1")
    Call WriteCtrl(ws, n, "IC-003", "Info Classification", "Confidential Data Protection", _
        "Confidential or Secret information must be protected to preserve confidentiality and integrity", _
            "Implement encryption at rest and in transit; restrict access via ACLs", _
        "Verify encryption settings; test ACLs", "Database,File Storage", "DataClass=Confidential OR DataClass=Secret", "MUST-HAVE", "Std 2.2.1")
    Call WriteCtrl(ws, n, "IC-004", "Info Classification", "Distribution Control", _
        "Distribution of Confidential/Secret information restricted to authorised parties", _
        "Implement DLP tools; restrict email/share permissions", "Test DLP rules; review sharing logs", "All", _
            "DataClass=Confidential OR DataClass=Secret", _
            "MUST-HAVE", _
        "Std 2.2.1")
    Call WriteCtrl(ws, n, "IC-005", "Info Classification", "Data Encryption", _
        "Encryption mandatory for electronic information classified as Confidential or Secret", _
        "Use AES-256 at rest; TLS 1.2+ in transit", "Verify cipher suites and encryption configs", "All", "DataClass=Confidential OR DataClass=Secret", _
            "MUST-HAVE", _
            "Std 2.2.1")
    ' Secure-by-Design
    Call WriteCtrl(ws, n, "SBD-001", "Secure-by-Design", "SBD Principles", _
        "Secure-by-Design principles shall be adopted for new or refreshed systems alongside SDLC", _
        "Integrate security requirements into each SDLC phase", "Review SDLC documentation for security gates", "All", "ALWAYS", "MUST-HAVE", "Std 4.2.1")
    Call WriteCtrl(ws, n, "SBD-002", "Secure-by-Design", "Risk Assessment", _
        "Cybersecurity risk assessment shall be conducted during initial planning phase", _
        "Perform threat modelling and risk assessment before development", "Review risk assessment report", "All", "ALWAYS", "MUST-HAVE", "Std 4.2.1")
    Call WriteCtrl(ws, n, "SBD-003", "Secure-by-Design", "Classification", "System owner must determine security criticality and classification level", _
        "Document system classification aligned with data sensitivity", "Verify classification documentation", "All", "ALWAYS", "MUST-HAVE", "Std 4.2.1")
    Call WriteCtrl(ws, n, "SBD-004", "Secure-by-Design", "Control Testing", "Security controls must be tested before and after commissioning", _
        "Conduct SAST/DAST/pentest pre- and post-go-live", "Review test reports and remediation evidence", "All", "ALWAYS", "MUST-HAVE", "Std 4.2.1")
    Call WriteCtrl(ws, n, "SBD-005", "Secure-by-Design", "Annual Risk Review", "Annual risk assessment for critical systems", _
        "Schedule annual risk review; update risk register", _
        "Review annual risk assessment report", "All", "RiskLevel=High OR Criticality=High", "MUST-HAVE", "Std 4.2.1")
    ' Security Hardening
    Call WriteCtrl(ws, n, "SH-001", "Sec Hardening", "Config Documents", "Security configuration documents for OS, application," & _
        "network and security appliances", _
        "Create hardening baselines; reference CIS benchmarks", "Compare configs against baselines", "All", "ALWAYS", "MUST-HAVE", "Std 4.2.2")
    Call WriteCtrl(ws, n, "SH-002", "Sec Hardening", "CIS Benchmarks", "Reference industry security benchmarks (CIS) for hardening", _
        "Download and apply CIS benchmarks per technology", "Run CIS-CAT or equivalent scanner", "All", "Deployment!=SaaS", "MUST-HAVE", "Std 4.2.2")
    Call WriteCtrl(ws, n, "SH-003", "Sec Hardening", "Least Privilege", "Enforce least privilege access and separation of duties", _
        "Configure role-based access; remove unnecessary admin rights", "Audit user permissions against role definitions", "All", "ALWAYS", "MUST-HAVE", _
            "Std 4.2.2")
    Call WriteCtrl(ws, n, "SH-004", "Sec Hardening", "Password Policy", "Enforce password complexity and policies on all systems", _
        "Min 8 user/12 admin/14 service; 3-of-4 complexity; 90-day rotation", "Review password policy settings", "All", "ALWAYS", "MUST-HAVE", "Std 4.2.2")
    Call WriteCtrl(ws, n, "SH-005", "Sec Hardening", "Default Accounts", "Disable/delete all default and unused accounts", _
        "Identify and disable default/guest accounts; document exceptions", "Scan for default accounts", "All", "Deployment!=SaaS", "MUST-HAVE", _
            "Std 4.2.2")
    Call WriteCtrl(ws, n, "SH-006", "Sec Hardening", "Unnecessary Services", "Remove unnecessary services, applications, and unused network ports", _
        "Audit running services; disable non-essential; close unused ports", "Run port scan and service enumeration", "All", "Deployment!=SaaS", _
            "MUST-HAVE", _
            "Std 4.2.2")
    Call WriteCtrl(ws, n, "SH-007", "Sec Hardening", "Anti-Malware", "Implement protection against malware", _
        "Deploy approved anti-malware on endpoints and servers", _
        "Verify agent status and signature dates", "Web Application,Application Server", "Deployment!=SaaS", "MUST-HAVE", "Std 4.2.2")
    Call WriteCtrl(ws, n, "SH-008", "Sec Hardening", "Patch Management", "Timely update of software and security patches", _
        "Establish patching schedule; critical patches within 30 days", "Review patch compliance report", "All", "Deployment!=SaaS", "MUST-HAVE", _
            "Std 4.2.2")
    Call WriteCtrl(ws, n, "SH-009", "Sec Hardening", "Login Logging", "All login attempts shall be logged", _
        "Enable auth logging on all systems; forward to SIEM", _
        "Verify login events in centralized logs", "All", "ALWAYS", "MUST-HAVE", "Std 4.2.2")
    ' Dev Environment
    Call WriteCtrl(ws, n, "DE-001", "Dev Environment", "Env Segregation", "Development environment must be segregated from production", _
        "Separate networks/subscriptions for dev and prod", "Verify network segmentation between environments", "All", "ALWAYS", "MUST-HAVE", "Std 4.2.3")
    Call WriteCtrl(ws, n, "DE-002", "Dev Environment", "No Dev-Prod Link", "Development systems must not be connected to production facilities", _
        "Ensure no network routes from dev to prod", "Test connectivity from dev to prod (should fail)", "All", "ALWAYS", "MUST-HAVE", "Std 4.2.3")
    Call WriteCtrl(ws, n, "DE-003", "Dev Environment", "Code Review", "All source code shall undergo review before production deployment", _
        "Implement mandatory code review (peer review or SAST)", "Review code review logs and approval records", "All", "ALWAYS", "MUST-HAVE", "Std 4.2.3")
    Call WriteCtrl(ws, n, "DE-004", "Dev Environment", "Dev Access Restrict", "Dev personnel shall not have unrestricted access to production data", _
        "Restrict dev access to prod; use masked/synthetic data", "Audit dev team production access permissions", "All", "ALWAYS", "MUST-HAVE", _
            "Std 4.2.3")
    ' App Security
    Call WriteCtrl(ws, n, "AS-001", "App Security", "App Ownership", "Information asset/system owner must be identified for new applications", _
        "Designate and document application owner", "Verify owner assignment in asset register", "Web Application,Application Server,API Gateway", _
            "ALWAYS", _
            "MUST-HAVE", _
        "Std 7.2.1")
    Call WriteCtrl(ws, n, "AS-002", "App Security", "Security Risk Assessment", "Information security risk assessment during planning phase", _
        "Conduct threat model and risk assessment before design", "Review risk assessment documentation", _
            "Web Application,Application Server,API Gateway", _
            "ALWAYS", _
            "MUST-HAVE", _
        "Std 7.2.1")
    Call WriteCtrl(ws, n, "AS-003", "App Security", "Auth & Authz", "Access to applications must be authenticated and authorised (least privilege)", _
        "Implement RBAC; enforce auth on all endpoints; use OAuth/SAML", "Test unauthenticated access; verify RBAC config", _
            "Web Application,Application Server,API Gateway", _
        "ALWAYS", "MUST-HAVE", "Std 7.2.2")
    Call WriteCtrl(ws, n, "AS-004", "App Security", "Unused Interfaces", "Unused application services/interfaces shall be disabled or removed", _
        "Audit exposed endpoints; disable unused APIs", "Run API discovery scan; compare to documented interfaces", "Web Application,API Gateway", _
            "ALWAYS", _
            "MUST-HAVE", _
        "Std 7.2.2")
    Call WriteCtrl(ws, n, "AS-005", "App Security", "Data Flow Docs", "Process detailed with Data Flow and Process Flow Diagrams per ARB requirements", _
        "Create DFD showing all data flows; submit to ARB", "Review DFD for completeness and ARB approval", "All", "ALWAYS", "MUST-HAVE", "Std 7.2.2")
    Call WriteCtrl(ws, n, "AS-006", "App Security", "Input Validation", "Controls shall be designed for data input validation", _
        "Implement server-side validation; use allowlists; encode outputs", "Test with OWASP validation test cases", "Web Application,API Gateway", _
            "ALWAYS", _
            "MUST-HAVE", _
        "Std 7.2.2")
    Call WriteCtrl(ws, n, "AS-007", "App Security", "Output Validation", "Data output validation controls to ensure correct output", _
        "Implement output encoding; validate response data formats", "Test output with boundary/malformed data", "Web Application,API Gateway", "ALWAYS", _
            "SHOULD-HAVE", _
        "Std 7.2.2")
    Call WriteCtrl(ws, n, "AS-008", "App Security", "Module Boundaries", "Application design must define clear logical boundaries between modules", _
        "Use layered/modular architecture; enforce separation of concerns", "Review architecture for proper module isolation", "Application Server", _
            "ALWAYS", _
            "SHOULD-HAVE", _
        "Std 7.2.2")
    Call WriteCtrl(ws, n, "AS-009", "App Security", "Audit Trails", "Applications shall provide audit trails per security policies", _
        "Log all CRUD on sensitive data; include user," & _
        "timestamp, action", "Verify audit log entries for key operations", "All", "ALWAYS", "MUST-HAVE", "Std 7.2.2")
    Call WriteCtrl(ws, n, "AS-010", "App Security", "Secure Protocols", "Application interfaces shall use secure protocols (SFTP, TLS, IPSec)", _
        "Use TLS 1.2+ for all inter-system comms; disable legacy protocols", "Scan for insecure protocol usage", "All", "ALWAYS", "MUST-HAVE", "Std 7.2.2")
    Call WriteCtrl(ws, n, "AS-011", "App Security", "Multi-Tier Architecture", "System shall use multi-tier architecture (Web/App/Data) where possible", _
        "Separate presentation," & _
        "logic, data tiers; use network segmentation", "Verify tier separation in architecture diagram", "Web Application,Application Server,Database", _
        "AppArch=3-Tier OR AppArch=N-Tier", "SHOULD-HAVE", "Std 7.2.2")
    Call WriteCtrl(ws, n, "AS-012", "App Security", "UAT Environment", "Separate UAT from Production; for SaaS follow vendor security", _
        "Provision separate UAT env; restrict prod data in UAT", "Verify UAT exists separately from prod", "All", "ALWAYS", "MUST-HAVE", "Std 7.2.2")
    Call WriteCtrl(ws, n, "AS-013", "App Security", "Secure File Transfer", "All file transfers shall use company-approved SFTP", _
        "Configure SFTP; block FTP/unencrypted transfers", "Verify file transfer protocols in use", "File Storage", "FileTransfer=Yes", "MUST-HAVE", _
            "Std 7.2.2")
    Call WriteCtrl(ws, n, "AS-014", "App Security", "Centralised Auth", "Systems with COMPANY user base shall integrate with centralised authentication", _
        "Integrate with corporate SSO/LDAP/AD; avoid local auth", "Test SSO integration; verify no standalone auth", "Web Application,Application Server", _
            "ALWAYS", _
            "MUST-HAVE", _
        "Std 7.2.2")
    Call WriteCtrl(ws, n, "AS-015", "App Security", "No Payment Storage", "Payment card details must not be stored", _
        "Do not store PAN/CVV; use tokenisation or payment gateway", _
        "Scan database/files for payment card patterns", "Database,Application Server", "PaymentData=Yes", "MUST-HAVE", "Std 7.2.2")
    Call WriteCtrl(ws, n, "AS-016", "App Security", "Secure Code Review", "Secure code reviews during development", _
        "Implement SAST in CI/CD; conduct peer code reviews", _
        "Review SAST reports and code review records", "Web Application,Application Server,API Gateway", "ALWAYS", "MUST-HAVE", "Std 7.2.3")
    Call WriteCtrl(ws, n, "AS-017", "App Security", "Friendly URLs", "Application shall use user-friendly URLs; no exposed hostnames/ports", _
        "Configure reverse proxy/LB; use clean URL routing", "Check URLs for exposed server names or ports", "Web Application", "InternetFacing=Yes", _
            "SHOULD-HAVE", _
            "Std 7.2.3")
    Call WriteCtrl(ws, n, "AS-018", "App Security", "Port 443 Only", "Application websites shall only use port 443 unless justified", _
        "Configure web server on port 443 only; document exceptions", "Scan for non-443 web ports", "Web Application", "InternetFacing=Yes", "MUST-HAVE", _
            "Std 7.2.3")
    Call WriteCtrl(ws, n, "AS-019", "App Security", "No Prod Data in Test", "Production data shall not be used for testing", _
        "Use data masking/synthetic data for test environments", "Verify test data origin; check for real PII in test DB", "Database,Application Server", _
            "ALWAYS", _
            "MUST-HAVE", _
        "Std 7.2.4")
    Call WriteCtrl(ws, n, "AS-020", "App Security", "Stress Testing", "Adequate stress and volume testing shall be performed", _
        "Conduct load/stress tests pre-launch", _
        "Review load test results and benchmarks", "Web Application,Application Server", "ALWAYS", "SHOULD-HAVE", "Std 7.2.4")
    Call WriteCtrl(ws, n, "AS-021", "App Security", "Security Testing", "Security controls must be tested and verified", _
        "Conduct DAST/pentest; verify controls function correctly", "Review pentest report and remediation status", "All", "ALWAYS", "MUST-HAVE", _
            "Std 7.2.4")
    Call WriteCtrl(ws, n, "AS-022", "App Security", "Backup & Recovery", "Backup and recovery process tested and documented before deployment", _
        "Implement backup schedule; test recovery; document RTO/RPO", "Verify backup logs and recovery drill results", "Database,File Storage", "ALWAYS", _
            "MUST-HAVE", _
            "Std 7.2.4")
    Call WriteCtrl(ws, n, "AS-023", "App Security", "Annual VA", "Vulnerability Assessment at least once a year", _
        "Schedule annual VA scans; use approved tools", _
        "Review VA reports and remediation plans", "All", "ALWAYS", "MUST-HAVE", "Std 7.2.4")
    ' Access Control
    Call WriteCtrl(ws, n, "AC-001", "Access Control", "System Access Control", "Implement access control to protect data and resources", _
        "Configure RBAC/ABAC; enforce least privilege", "Audit access control configuration", "All", "ALWAYS", "MUST-HAVE", "Std 8.2.1")
    Call WriteCtrl(ws, n, "AC-002", "Access Control", "Need-to-Know", "Access controlled on need-to-know and least privilege basis", _
        "Implement data access policies; restrict based on role", "Review access lists against role definitions", "All", "ALWAYS", "MUST-HAVE", _
            "Std 8.2.1")
    Call WriteCtrl(ws, n, "AC-003", "Access Control", "Access Procedures", "Access authorisation/de-authorisation procedures documented", _
        "Create joiner/mover/leaver procedures aligned with ITIL", "Review access management procedures and logs", "All", "ALWAYS", "MUST-HAVE", _
            "Std 8.2.1")
    Call WriteCtrl(ws, n, "AC-004", "Access Control", "Login Banner", "Banner displayed before logon informing users of policies", _
        "Configure pre-auth banner on all login screens", "Verify banner display on login pages", "Web Application,Application Server", "ALWAYS", _
            "SHOULD-HAVE", _
            "Std 8.2.1")
    Call WriteCtrl(ws, n, "AC-005", "Access Control", "Logon Controls", "Limit invalid logon attempts; minimal system info during logon", _
        "Lockout after 5 failed attempts; hide system version", "Test lockout; verify no system info disclosure", "All", "ALWAYS", "MUST-HAVE", _
            "Std 8.2.1")
    Call WriteCtrl(ws, n, "AC-006", "Access Control", "No Bypass Features", "Features enabling bypass of controls must be removed/disabled", _
        "Audit for debug modes," & _
        "backdoors; disable all", "Security scan for bypass capabilities", "Web Application,Application Server", "ALWAYS", "MUST-HAVE", "Std 8.2.1")
    Call WriteCtrl(ws, n, "AC-007", "Access Control", "RBAC/ABAC", "Role-based and attribute-based access control with conflict detection", _
        "Implement RBAC with SoD conflict rules", "Test role assignments and SoD detection", "All", "ALWAYS", "MUST-HAVE", "Std 8.2.1")
    Call WriteCtrl(ws, n, "AC-008", "Access Control", "Account Mgmt Procs", "Account management procedures (create/modify/delete/suspend) per ITIL", _
        "Document full account lifecycle procedures", "Audit account management compliance", "All", "ALWAYS", "MUST-HAVE", "Std 8.2.2")
    Call WriteCtrl(ws, n, "AC-009", "Access Control", "Annual Access Review", "Review all accounts and access privileges annually", _
        "Schedule annual access certification; revoke stale access", "Review certification and revocation records", "All", "ALWAYS", "MUST-HAVE", _
            "Std 8.2.2")
    Call WriteCtrl(ws, n, "AC-010", "Access Control", "Timely Deprovisioning", "Access removed immediately when no longer required", _
        "Integrate with HR termination; automate deprovisioning", "Test deprovisioning SLA; audit terminated accounts", "All", "ALWAYS", "MUST-HAVE", _
            "Std 8.2.2")
    Call WriteCtrl(ws, n, "AC-011", "Access Control", "No Shared Accounts", "Accounts shall not be shared unless explicitly approved", _
        "No shared accounts policy; document exceptions", "Audit for shared account usage", "All", "ALWAYS", "MUST-HAVE", "Std 8.2.2")
    ' Privileged Access
    Call WriteCtrl(ws, n, "PA-001", "Privileged Access", "PAM Procedures", "Procedures for privileged account issue and use per ITIL", _
        "Implement PAM tool; document procedures", _
        "Review PAM config and procedures", "All", "PrivAccounts=Yes", "MUST-HAVE", "Std 8.2.3")
    Call WriteCtrl(ws, n, "PA-002", "Privileged Access", "Revoke When Unused", "Privileged access revoked when no longer required", _
        "Time-limited sessions; quarterly review", _
        "Audit privileged account usage", "All", "PrivAccounts=Yes", "MUST-HAVE", "Std 8.2.3")
    Call WriteCtrl(ws, n, "PA-003", "Privileged Access", "Authorised Only", "Privileged IDs only for personnel managing the system", _
        "Restrict to system admins; require justification", "Review holders vs admin roles", "All", "PrivAccounts=Yes", "MUST-HAVE", "Std 8.2.3")
    Call WriteCtrl(ws, n, "PA-004", "Privileged Access", "No Privilege Abuse", "Personnel must not use privileged accounts for normal activities", _
        "Separate admin and user accounts; monitor usage", "Audit admin activity for non-admin tasks", "All", "PrivAccounts=Yes", "MUST-HAVE", "Std 8.2.3")
    Call WriteCtrl(ws, n, "PA-005", "Privileged Access", "Password Security", "Privileged passwords kept securely; usage approved and logged", _
        "Store in password vault; enforce checkout/checkin", "Verify vault usage and checkout logs", "All", "PrivAccounts=Yes", "MUST-HAVE", "Std 8.2.3")
    Call WriteCtrl(ws, n, "PA-006", "Privileged Access", "No Sharing", "Sharing of privileged accounts is prohibited", "Unique privileged IDs per person", _
        "Audit for shared privileged accounts", "All", "PrivAccounts=Yes", "MUST-HAVE", "Std 8.2.3")
    ' MFA
    Call WriteCtrl(ws, n, "MF-001", "MFA", "MFA Enforcement", "MFA enforced for user and administrator accounts", _
        "Enable MFA on all authentication; use corporate MFA", _
        "Test MFA enforcement; verify enrollment", "All", "ALWAYS", "MUST-HAVE", "Std 8.2.4")
    Call WriteCtrl(ws, n, "MF-002", "MFA", "MFA for Privileged", "MFA for privileged accounts", "Step-up MFA for all privileged operations", _
        "Test privileged access without MFA (should fail)", "All", "PrivAccounts=Yes", "MUST-HAVE", "Std 8.2.4")
    ' Password Mgmt
    Call WriteCtrl(ws, n, "PW-001", "Password Mgmt", "Password Length", "Min 8 user/12 admin/14 service; 3-of-4 complexity", _
        "Configure password policy in IdP/system settings", _
        "Review password policy config", "All", "ALWAYS", "MUST-HAVE", "Std 8.2.5")
    Call WriteCtrl(ws, n, "PW-002", "Password Mgmt", "Password Rotation", "User/admin passwords changed every 90 days; service annually", _
        "Configure expiry policies; notify users", "Verify password age against policy", "All", "ALWAYS", "MUST-HAVE", "Std 8.2.5")
    Call WriteCtrl(ws, n, "PW-003", "Password Mgmt", "Password History", "Last 12 passwords must not be reused", _
        "Configure history enforcement (12 passwords)", _
        "Test password reuse (should be rejected)", "All", "ALWAYS", "MUST-HAVE", "Std 8.2.5")
    Call WriteCtrl(ws, n, "PW-004", "Password Mgmt", "Password Masking", "Passwords masked/suppressed during display", _
        "Input masking on all password fields; no plain text logging", "Verify masking on forms; check logs", "Web Application,Application Server", _
            "ALWAYS", _
            "MUST-HAVE", _
        "Std 8.2.5")
    ' Audit Trail
    Call WriteCtrl(ws, n, "AT-001", "Audit Trail", "Security Audit Logs", _
        "Audit logs must include sufficient info for detection and investigation", _
        "Log auth, authz changes, system events, network activity", "Review log content for required event types", "All", "ALWAYS", "MUST-HAVE", "Std 8.2.7")
    Call WriteCtrl(ws, n, "AT-002", "Audit Trail", "SaaS Audit Logs", "For SaaS/cloud, audit logs available to COMPANY on request", _
        "Verify vendor log access; configure log export/SIEM", "Test audit log retrieval from vendor", "All", "Deployment=SaaS", "MUST-HAVE", "Std 8.2.7")
    Call WriteCtrl(ws, n, "AT-003", "Audit Trail", "No Passwords in Logs", "Passwords must not be recorded in audit logs", _
        "Configure logging to exclude passwords; use masking", _
        "Search logs for password patterns", "All", "ALWAYS", "MUST-HAVE", "Std 8.2.7")
    Call WriteCtrl(ws, n, "AT-004", "Audit Trail", "Log Monitoring", "Procedures for monitoring/review of audit logs", _
        "Establish log review schedule; configure SIEM alerts", _
        "Review monitoring procedures and alerts", "All", "ALWAYS", "MUST-HAVE", "Std 8.2.7")
    Call WriteCtrl(ws, n, "AT-005", "Audit Trail", "Log Retention", "Audit log retention min 12 months for security devices", _
        "Configure retention >= 12 months; archive older logs", "Verify oldest logs meet retention requirement", "All", "ALWAYS", "MUST-HAVE", "Std 8.2.7")
    ' Network Security
    Call WriteCtrl(ws, n, "NS-001", "Network Security", "Network Boundary", "Network boundary clearly defined, documented and updated", _
        "Create/maintain network diagrams; define zone boundaries", "Review network documentation", "All", "ALWAYS", "MUST-HAVE", "Std 9.2.1")
    Call WriteCtrl(ws, n, "NS-002", "Network Security", "Network Documentation", "Docs include device diagrams, zone definitions, ACLs, FW rules", _
        "Maintain topology diagrams," & _
        "zone maps, ACLs, routing tables", "Audit documentation completeness", "All", "Deployment!=SaaS", "MUST-HAVE", "Std 9.2.1")
    Call WriteCtrl(ws, n, "NS-003", "Network Security", "Zone Segmentation", "Network segmented by purpose, function, and security needs", _
        "Implement VLANs/subnets for zones; enforce ACLs", "Verify segmentation via network scan", "All", "Deployment!=SaaS", "MUST-HAVE", "Std 9.2.1")
    Call WriteCtrl(ws, n, "NS-004", "Network Security", "Network Access Control", "Physical access to network equipment restricted", _
        "Implement physical access controls for network rooms", "Audit physical access logs", "All", "Deployment=On-Premises OR Deployment=Hybrid", _
            "MUST-HAVE", _
            "Std 9.2.2")
    Call WriteCtrl(ws, n, "NS-005", "Network Security", "Secure Mgmt Access", "Network equipment access through secure channel with auth/logging", _
        "Use SSH/HTTPS for mgmt; require MFA; enable logging", "Verify management access protocols", "All", "Deployment!=SaaS", "MUST-HAVE", "Std 9.2.2")
    Call WriteCtrl(ws, n, "NS-006", "Network Security", "Config Documentation", "Network configs documented and kept current", _
        "Maintain CMDB with current configs; version control", "Compare documented vs actual configs", "All", "Deployment!=SaaS", "MUST-HAVE", "Std 9.2.2")
    Call WriteCtrl(ws, n, "NS-007", "Network Security", "Network Monitoring", "Monitoring tools shall log activities and security violations", _
        "Deploy SIEM/NDR; monitor for anomalies", "Verify monitoring coverage and alerts", "All", "ALWAYS", "MUST-HAVE", "Std 9.2.2")
    Call WriteCtrl(ws, n, "NS-008", "Network Security", "Network Log Retention", "Network equipment logs kept min 60 days", _
        "Configure log retention >= 60 days", _
        "Check oldest network logs", "All", "Deployment!=SaaS", "MUST-HAVE", "Std 9.2.2")
    Call WriteCtrl(ws, n, "NS-009", "Network Security", "Disable Unused Ports", "Unused network ports shall be disabled", _
        "Audit switch ports; disable unused", _
        "Scan for open unused ports", "All", "Deployment!=SaaS", "MUST-HAVE", "Std 9.2.2")
    Call WriteCtrl(ws, n, "NS-010", "Network Security", "Annual Security Review", "Annual security review of network infrastructure", _
        "Schedule annual network security audit", _
        "Review audit report", "All", "ALWAYS", "SHOULD-HAVE", "Std 9.2.3")
    Call WriteCtrl(ws, n, "NS-011", "Network Security", "IDS/IPS", "Network IDS/IPS with 24x7 monitoring for internet connections", _
        "Deploy IDS/IPS at perimeter; connect to SOC", _
        "Verify IDS/IPS alerts and monitoring", "All", "InternetFacing=Yes", "MUST-HAVE", "Std 9.2.3")
    Call WriteCtrl(ws, n, "NS-012", "Network Security", "DDoS Protection", "Network DDoS protection with 24x7 monitoring", _
        "Implement DDoS mitigation; connect to SOC", _
        "Test DDoS protection; verify monitoring", "Web Application,API Gateway,Load Balancer", "InternetFacing=Yes", "MUST-HAVE", "Std 9.2.3")
    Call WriteCtrl(ws, n, "NS-013", "Network Security", "Incident Response", "Procedures to monitor and respond to security incidents", _
        "Establish IR procedures; integrate with CSIRT", "Review IR procedures; test with tabletop", "All", "ALWAYS", "MUST-HAVE", "Std 9.2.3")
    Call WriteCtrl(ws, n, "NS-014", "Network Security", "Incident Reporting", "All incidents immediately reported to Cybersecurity", _
        "Define reporting channels; train staff", _
        "Review incident reports and response times", "All", "ALWAYS", "MUST-HAVE", "Std 9.2.3")
    Call WriteCtrl(ws, n, "NS-015", "Network Security", "Security Log Retention", "Security device/firewall logs stored min 12 months", _
        "Configure retention >= 12 months", _
        "Verify oldest security logs", "All", "ALWAYS", "MUST-HAVE", "Std 9.2.3")
    ' Remote Access
    Call WriteCtrl(ws, n, "RA-001", "Remote Access", "Remote Access Infra", "All remote access via consolidated infrastructure", "Use corporate VPN/ZTNA", _
        "Verify all remote access routes through approved infra", "All", "RemoteAccess=Yes", "MUST-HAVE", "Std 9.2.4")
    Call WriteCtrl(ws, n, "RA-002", "Remote Access", "Remote MFA", "All remote access authenticated using MFA", "Enable MFA on VPN/remote access gateway", _
        "Test remote access without MFA (should fail)", "All", "RemoteAccess=Yes", "MUST-HAVE", "Std 9.2.4")
    Call WriteCtrl(ws, n, "RA-003", "Remote Access", "Remote Access Logging", "All remote access activities logged", _
        "Enable detailed logging on VPN; forward to SIEM", _
        "Verify remote access events in logs", "All", "RemoteAccess=Yes", "MUST-HAVE", "Std 9.2.4")
    ' Firewall
    Call WriteCtrl(ws, n, "FW-001", "Firewall", "Rule Documentation", "Firewall rules documented, checked and reviewed annually", _
        "Maintain FW rule docs; schedule annual review", _
        "Review FW documentation and review records", "All", "Deployment!=SaaS", "MUST-HAVE", "Std 9.2.5")
    Call WriteCtrl(ws, n, "FW-002", "Firewall", "Fail-Safe", "Firewall fail-safe; default deny on failure/reboot", "Configure fail-closed; test failover", _
        "Test FW behaviour during failure", "All", "Deployment!=SaaS", "MUST-HAVE", "Std 9.2.5")
    Call WriteCtrl(ws, n, "FW-003", "Firewall", "Daily Backup", "Firewall configs backed up daily", "Automated daily backup; trigger on change", _
        "Verify backup schedule and restore capability", "All", "Deployment!=SaaS", "MUST-HAVE", "Std 9.2.5")
    Call WriteCtrl(ws, n, "FW-004", "Firewall", "Default Deny", "Firewall deny all unless explicitly permitted", _
        "Default deny inbound/outbound; whitelist required", _
        "Verify default deny is last rule", "All", "Deployment!=SaaS", "MUST-HAVE", "Std 9.2.5")
    Call WriteCtrl(ws, n, "FW-005", "Firewall", "Specific Rules", "Firewall rules limited to specific IPs, ports, applications", _
        "Specific source/dest; avoid any rules; document need", "Audit for overly permissive rules", "All", "Deployment!=SaaS", "MUST-HAVE", "Std 9.2.5")
    Call WriteCtrl(ws, n, "FW-006", "Firewall", "Session Decoupling", "Internet-facing FW decouples external and internal sessions", _
        "Configure reverse proxy/WAF to terminate external sessions", "Verify external sessions don't reach internal directly", _
            "Web Application,API Gateway", _
        "InternetFacing=Yes", "MUST-HAVE", "Std 9.2.5")
    Call WriteCtrl(ws, n, "FW-007", "Firewall", "Firewall Logging", "Firewall logs and audit trails activated and archived", _
        "Enable comprehensive logging; archive per policy", _
        "Verify FW logs generated and archived", "All", "Deployment!=SaaS", "MUST-HAVE", "Std 9.2.5")
    ' Encryption
    Call WriteCtrl(ws, n, "EN-001", "Encryption", "Data Encryption", "Data encrypted for storing, transmitting, and processing", _
        "AES-256 at rest; TLS 1.2+ in transit", _
        "Verify encryption config for storage and transit", "All", "DataClass=Restricted+", "MUST-HAVE", "Std 10.2.6")
    Call WriteCtrl(ws, n, "EN-002", "Encryption", "Storage Encryption", "Sensitive info encrypted by secure cryptographic mechanism", _
        "AES-256 for database/file encryption at rest", "Verify database and storage encryption", "Database,File Storage", _
            "DataClass=Confidential OR DataClass=Secret", _
        "MUST-HAVE", "Std 10.2.6")
    Call WriteCtrl(ws, n, "EN-003", "Encryption", "Transport Encryption", "Transport-level encryption for data in transit", _
        "TLS 1.2+ for all transit; disable legacy versions", _
        "SSL/TLS scan; verify cipher suites", "All", "ALWAYS", "MUST-HAVE", "Std 10.2.6")
    Call WriteCtrl(ws, n, "EN-004", "Encryption", "Internet TLS Cert", "Internet apps: SHA-256 TLS cert from authorised CA", _
        "Install SHA-256+ cert from approved public CA", _
        "Verify cert chain, expiry, SHA-256", "Web Application,Load Balancer", "InternetFacing=Yes", "MUST-HAVE", "Std 10.2.6")
    Call WriteCtrl(ws, n, "EN-005", "Encryption", "Intranet TLS Cert", "Intranet apps: SHA-256 cert from internal CA", "Install internal CA cert", _
        "Verify internal certificate config", "Web Application,Load Balancer", "InternetFacing=No", "MUST-HAVE", "Std 10.2.6")
    Call WriteCtrl(ws, n, "EN-006", "Encryption", "SaaS TLS Cert", "SaaS: SHA-256 cert from reputable public CA", _
        "Verify vendor uses SHA-256+ from reputable CA", _
        "Check SaaS application certificate", "All", "Deployment=SaaS", "MUST-HAVE", "Std 10.2.6")
    Call WriteCtrl(ws, n, "EN-007", "Encryption", "Cert Management", "Certificates managed and replaced before expiry", _
        "Certificate monitoring; alert 30 days before expiry", _
        "Review expiry dates across endpoints", "All", "ALWAYS", "MUST-HAVE", "Std 10.2.6")
    Call WriteCtrl(ws, n, "EN-008", "Encryption", "Secure Protocols", "Use HTTPS, SFTP, SSH, DNSSEC, SMTPS (TLS 1.2+)", "Disable HTTP, FTP," & _
        "Telnet; enforce encrypted alternatives", "Scan for unencrypted protocol usage", "All", "ALWAYS", "MUST-HAVE", "Std 10.2.6")
End Sub

Sub LoadSaaSControls(ws As Worksheet, n As Long)
    Call WriteCtrl(ws, n, "SAAS-001", "SaaS Security", "SSO SAML/OIDC", _
        "SaaS must support SAML 2.0 or OIDC for auth with enterprise IdPs (Entra/Azure AD/Okta); support SP and IdP-initiated flows; disable native" & _
            "login", _
        "Configure SSO via OIDC (preferred) or SAML 2.0; disable native login after SSO is confirmed", _
        "Verify SSO integration; test both SP and IdP-initiated flows; confirm native login disabled", "All", "Deployment=SaaS", "MUST-HAVE", _
            "SaaS Req 1.1")
    Call WriteCtrl(ws, n, "SAAS-002", "SaaS Security", "Log Tamper Protection", _
        "Audit logs must be immutable/tamper-proof; timestamps synchronized with NTP", _
        "Verify vendor logs are append-only; confirm NTP sync", "Request vendor attestation of log immutability; verify timestamps", "All", _
            "Deployment=SaaS", _
            "MUST-HAVE", _
        "SaaS Req 1.4")
    Call WriteCtrl(ws, n, "SAAS-003", "SaaS Security", "SIEM Log Export", "Platform must support exporting logs to external SIEM/log repository", _
        "Configure log forwarding to corporate SIEM; verify all event types", "Test SIEM integration; validate log completeness", "All", _
            "Deployment=SaaS", _
            "MUST-HAVE", _
        "SaaS Req 1.4")
    Call WriteCtrl(ws, n, "SAAS-004", "SaaS Security", "Disable Weak TLS/Ciphers", _
        "Disable TLS 1.0/1.1 and weak ciphers; TLS 1.3 first, TLS 1.2 fallback", _
        "Verify vendor disables legacy TLS/ciphers", "SSL Labs scan; verify cipher order", "All", "Deployment=SaaS", "MUST-HAVE", "SaaS Req 2.2")
    Call WriteCtrl(ws, n, "SAAS-005", "SaaS Data", "Customer-Managed Keys (BYOK)", "Support CMK/BYOK with annual key rotation, revocation," & _
        "and key usage audit logging", _
        "Integrate with customer key mgmt (Azure Key Vault); configure rotation; enable audit", _
            "Verify BYOK config; test rotation; review key audit logs", _
            "All", _
        "Deployment=SaaS", "SHOULD-HAVE", "SaaS Req 2.3")
    Call WriteCtrl(ws, n, "SAAS-006", "SaaS Data", "Data Residency & Sovereignty", _
        "Data stored in customer-specified regions; separated by region and tenant", _
        "Confirm data residency region; verify in contract; ensure regional compliance", _
            "Request vendor docs of data location; verify regional deployment", _
            "All", _
        "Deployment=SaaS", "MUST-HAVE", "SaaS Req 2.4")
    Call WriteCtrl(ws, n, "SAAS-007", "SaaS Data", "Tenant Isolation", "Dedicated tenant required (not shared); must reside in region where managed", _
        "Verify single-tenant or logically isolated; confirm no shared tenancy", "Review vendor architecture; test for cross-tenant leakage", "All", _
            "Deployment=SaaS", _
        "MUST-HAVE", "SaaS Req 2.4")
    Call WriteCtrl(ws, n, "SAAS-008", "SaaS Data", "Data Retention & Deletion", _
        "Customer-defined retention; permanent deletion within 72hrs using NIST 800-88", _
        "Agree retention schedule; verify NIST 800-88 deletion; include in contract", _
            "Test deletion request; verify from backups/DR; get vendor attestation", _
            "All", _
        "Deployment=SaaS", "MUST-HAVE", "SaaS Req 2.5")
    Call WriteCtrl(ws, n, "SAAS-009", "SaaS Data", "Termination Data Purge", "On termination," & _
        "all data permanently deleted from all systems incl backups/DR/HA", _
        "Termination deletion clause in contract; define verification process", "Request deletion certificate; verify no residual data", "All", _
            "Deployment=SaaS", _
            "MUST-HAVE", _
        "SaaS Req 2.5")
    Call WriteCtrl(ws, n, "SAAS-010", "SaaS Assurance", "3rd-Party Pentest Evidence", _
        "Vendor must provide 3rd-party pentest evidence; critical internet findings fixed within 48hrs", _
            "Request pentest report under NDA; verify critical remediation timelines", _
        "Review report; verify critical fix within 48hrs", "All", "Deployment=SaaS", "MUST-HAVE", "SaaS Req 3.1")
    Call WriteCtrl(ws, n, "SAAS-011", "SaaS Assurance", "Secure SDLC & Key Vault", _
        "Vendor follows secure SDLC with threat modeling/automated testing; key vault for all secrets", _
        "Verify SSDLC practices; confirm key vault for secrets/API keys/tokens", "Review SSDLC docs; verify key vault implementation", "All", _
            "Deployment=SaaS", _
            "MUST-HAVE", _
        "SaaS Req 3.2")
    Call WriteCtrl(ws, n, "SAAS-012", "SaaS Compliance", "SOC2/ISO Certifications", _
        "Vendor holds SOC 2 Type II (Security,Confidentiality,Privacy) and/or ISO 27001; updated annually", _
            "Request current SOC 2 Type II / ISO 27001; verify annual renewal", _
        "Review certs; confirm currency and scope", "All", "Deployment=SaaS", "MUST-HAVE", "SaaS Req 4.1")
    Call WriteCtrl(ws, n, "SAAS-013", "SaaS Compliance", "DPA & Privacy Compliance", _
        "Execute DPA; outline data handling per GDPR/CCPA; disclose all subprocessors/subcontractors", _
        "Execute DPA; review subprocessors; verify lawful basis; include in contract", "Review signed DPA; verify subprocessor list; confirm compliance", _
            "All", _
            "Deployment=SaaS", _
        "MUST-HAVE", "SaaS Req 4.2")
    Call WriteCtrl(ws, n, "SAAS-014", "SaaS Compliance", "Breach Notification SLA", _
        "Notify within 24hrs of confirmed breach; full RCA and impact report within 5 business days", _
        "Include SLA in contract (24hr notify, 5-day RCA); define escalation paths", "Review contract SLAs; verify IR plan includes notification", "All", _
            "Deployment=SaaS", _
        "MUST-HAVE", "SaaS Req 4.3")
    Call WriteCtrl(ws, n, "SAAS-015", "SaaS API Security", "API OAuth 2.0 Auth", _
        "APIs must use OAuth 2.0 (preferred) or scoped keys/JWT; no long-lived/hardcoded static tokens", _
        "Configure OAuth 2.0; scope tokens to min permissions; implement rotation", "Test API auth; verify scoping; scan for static tokens", _
            "API Gateway", _
            "Deployment=SaaS", _
        "MUST-HAVE", "SaaS Req 5.1")
    Call WriteCtrl(ws, n, "SAAS-016", "SaaS API Security", "API Rate Limiting", _
        "Rate limits per client/user/IP to prevent DoS/DDoS; burst limits and throttling docs required", _
        "Verify vendor rate limiting; review developer docs for limits", "Test rate limits; verify HTTP 429; review throttling docs", "API Gateway", _
            "Deployment=SaaS", _
        "MUST-HAVE", "SaaS Req 5.1")
    Call WriteCtrl(ws, n, "SAAS-017", "SaaS API Security", "API Certificate Pinning", _
        "Certificate pinning enforced for mobile/API clients where feasible", _
        "Implement cert pinning for mobile and critical API clients", "Test pinning enforcement; verify rotation process", "API Gateway", _
            "Deployment=SaaS", _
            "SHOULD-HAVE", _
        "SaaS Req 5.1")
End Sub
' ============================================================
' SECURITY CHECKLIST (Dynamic with Enabled + Applicability)
' ============================================================
Sub BuildChecklist(wb As Workbook)
    Dim ws As Worksheet: Set ws = wb.Sheets("Security Checklist")
    Dim wsC As Worksheet: Set wsC = wb.Sheets("Controls Library")
    
    Dim hdrs As Variant
    hdrs = Array("#", "Control ID", "Domain", "Control Description", "Implementation Guidance", "Applicable Component", "Priority", "Verification Method", _
        "Status", _
        "Evidence/Notes", "Source Ref", "Enabled?", "Applicable?")
    Dim widths As Variant
    widths = Array(5, 12, 18, 45, 40, 22, 14, 30, 14, 30, 14, 10, 12)
    Dim j As Long
    For j = 0 To 12
        ws.Cells(1, j + 1).Value = hdrs(j): ws.Columns(j + 1).ColumnWidth = widths(j)
    Next j
    Call FmtHeader(ws.Range("A1:M1"))
    ws.Cells(1, 12).Interior.Color = RGB(255, 111, 0)
    ws.Cells(1, 13).Interior.Color = RGB(198, 40, 40)
    
    Dim lastCtrl As Long
    lastCtrl = wsC.Cells(wsC.Rows.Count, 1).End(xlUp).Row
    
    Dim r As Long, trigger As String
    For r = 2 To lastCtrl
        ws.Cells(r, 1).Value = r - 1
        ws.Cells(r, 2).Value = wsC.Cells(r, 1).Value: ws.Cells(r, 2).Font.Bold = True
        ws.Cells(r, 3).Value = wsC.Cells(r, 2).Value
        ws.Cells(r, 4).Value = wsC.Cells(r, 4).Value
        ws.Cells(r, 5).Value = wsC.Cells(r, 5).Value
        ws.Cells(r, 6).Value = wsC.Cells(r, 7).Value
        ws.Cells(r, 7).Value = wsC.Cells(r, 9).Value
        ws.Cells(r, 8).Value = wsC.Cells(r, 6).Value
        ws.Cells(r, 9).Interior.Color = RGB(255, 242, 204): ws.Cells(r, 9).Locked = False
        ws.Cells(r, 10).Interior.Color = RGB(255, 242, 204): ws.Cells(r, 10).Locked = False
        ws.Cells(r, 11).Value = wsC.Cells(r, 10).Value
        ws.Cells(r, 12).Formula = "='Controls Library'!K" & r
        
        trigger = CStr(wsC.Cells(r, 8).Value)
        ws.Cells(r, 13).Formula = GetAppFormula(trigger, r)
        
        Dim c As Long
        For c = 1 To 13
            ws.Cells(r, c).Font.Name = "Arial": ws.Cells(r, c).Font.Size = 10
            ws.Cells(r, c).WrapText = True: ws.Cells(r, c).VerticalAlignment = xlTop
            ws.Cells(r, c).Borders.LineStyle = xlContinuous
            ws.Cells(r, c).Borders.Color = RGB(191, 191, 191)
            If c <> 9 And c <> 10 Then ws.Cells(r, c).Locked = True
        Next c
    Next r
    
    ' Status dropdown
    With ws.Range("I2:I" & lastCtrl).Validation
        .Delete: .Add Type:=xlValidateList, AlertStyle:=xlValidAlertStop, Formula1:="=Lookups!$F$2:$F$5"
    End With
    
    ' Conditional formatting - Priority
    Dim rG As Range: Set rG = ws.Range("G2:G" & lastCtrl)
    rG.FormatConditions.Add Type:=xlCellValue, Operator:=xlEqual, Formula1:="=""MUST-HAVE"""
    rG.FormatConditions(rG.FormatConditions.Count).Interior.Color = RGB(252, 228, 236)
    rG.FormatConditions(rG.FormatConditions.Count).Font.Color = RGB(198, 40, 40)
    rG.FormatConditions(rG.FormatConditions.Count).Font.Bold = True
    rG.FormatConditions.Add Type:=xlCellValue, Operator:=xlEqual, Formula1:="=""SHOULD-HAVE"""
    rG.FormatConditions(rG.FormatConditions.Count).Interior.Color = RGB(255, 242, 204)
    rG.FormatConditions(rG.FormatConditions.Count).Font.Color = RGB(230, 81, 0)
    rG.FormatConditions(rG.FormatConditions.Count).Font.Bold = True
    rG.FormatConditions.Add Type:=xlCellValue, Operator:=xlEqual, Formula1:="=""NICE-TO-HAVE"""
    rG.FormatConditions(rG.FormatConditions.Count).Interior.Color = RGB(226, 239, 218)
    rG.FormatConditions(rG.FormatConditions.Count).Font.Color = RGB(46, 125, 50)
    rG.FormatConditions(rG.FormatConditions.Count).Font.Bold = True
    
    ' Status
    Dim rI As Range: Set rI = ws.Range("I2:I" & lastCtrl)
    rI.FormatConditions.Add Type:=xlCellValue, Operator:=xlEqual, Formula1:="=""Implemented"""
    rI.FormatConditions(rI.FormatConditions.Count).Interior.Color = RGB(226, 239, 218)
    rI.FormatConditions(rI.FormatConditions.Count).Font.Color = RGB(46, 125, 50)
    rI.FormatConditions.Add Type:=xlCellValue, Operator:=xlEqual, Formula1:="=""Not Started"""
    rI.FormatConditions(rI.FormatConditions.Count).Interior.Color = RGB(252, 228, 236)
    rI.FormatConditions(rI.FormatConditions.Count).Font.Color = RGB(198, 40, 40)
    rI.FormatConditions.Add Type:=xlCellValue, Operator:=xlEqual, Formula1:="=""In Progress"""
    rI.FormatConditions(rI.FormatConditions.Count).Interior.Color = RGB(255, 242, 204)
    rI.FormatConditions(rI.FormatConditions.Count).Font.Color = RGB(230, 81, 0)
    
    ' Enabled/Applicable = No
    ws.Range("L2:L" & lastCtrl).FormatConditions.Add Type:=xlCellValue, Operator:=xlEqual, Formula1:="=""No"""
    ws.Range("L2:L" & lastCtrl).FormatConditions(1).Interior.Color = RGB(217, 217, 217)
    ws.Range("L2:L" & lastCtrl).FormatConditions(1).Font.Color = RGB(153, 153, 153)
    ws.Range("M2:M" & lastCtrl).FormatConditions.Add Type:=xlCellValue, Operator:=xlEqual, Formula1:="=""No"""
    ws.Range("M2:M" & lastCtrl).FormatConditions(1).Interior.Color = RGB(217, 217, 217)
    ws.Range("M2:M" & lastCtrl).FormatConditions(1).Font.Color = RGB(153, 153, 153)
    
'    ws.Range("A1:M" & lastCtrl).AutoFilter
    On Error Resume Next
    ws.Activate
    ws.Range("A2").Select
    ActiveWindow.FreezePanes = True
    On Error GoTo 0
End Sub

Function GetAppFormula(trigger As String, r As Long) As String
    Dim tf As String
    Select Case trigger
        Case "ALWAYS"
            tf = """Yes"""
        Case "DataClass=Confidential OR DataClass=Secret"
            tf = "IF(OR('Project Profile'!D31=""Confidential"",'Project Profile'!D31=""Secret""),""Yes"",""No"")"
        Case "DataClass=Restricted+"
            tf = "IF(OR('Project Profile'!D31=""Restricted"",'Project Profile'!D31=""Confidential"",'Project Profile'!D31=""Secret""),""Yes"",""No"")"
        Case "Deployment!=SaaS"
            tf = "IF('Project Profile'!D13<>""SaaS"",""Yes"",""No"")"
        Case "Deployment=SaaS"
            tf = "IF('Project Profile'!D13=""SaaS"",""Yes"",""No"")"
        Case "Deployment=On-Premises OR Deployment=Hybrid"
            tf = "IF(OR('Project Profile'!D13=""On-Premises"",'Project Profile'!D13=""Hybrid""),""Yes"",""No"")"
        Case "RiskLevel=High OR Criticality=High"
            tf = "IF(OR('Project Profile'!D15=""High"",'Project Profile'!D16=""High""),""Yes"",""No"")"
        Case "PrivAccounts=Yes"
            tf = "IF('Project Profile'!D38=""Yes"",""Yes"",""No"")"
        Case "InternetFacing=Yes"
            tf = "IF('Project Profile'!D42=""Yes"",""Yes"",""No"")"
        Case "InternetFacing=No"
            tf = "IF('Project Profile'!D42=""No"",""Yes"",""No"")"
        Case "RemoteAccess=Yes"
            tf = "IF('Project Profile'!D45=""Yes"",""Yes"",""No"")"
        Case "FileTransfer=Yes"
            tf = "IF('Project Profile'!D46=""Yes"",""Yes"",""No"")"
        Case "PaymentData=Yes"
            tf = "IF('Project Profile'!D33=""Yes"",""Yes"",""No"")"
        Case "AppArch=3-Tier OR AppArch=N-Tier"
            tf = "IF(OR('Project Profile'!D14=""3-Tier"",'Project Profile'!D14=""N-Tier""),""Yes"",""No"")"
        Case Else
            tf = """Yes"""
    End Select
    GetAppFormula = "=IF(L" & r & "=""No"",""No""," & tf & ")"
End Function

' ============================================================
' DASHBOARD
' ============================================================
Sub BuildDashboard(wb As Workbook)
    Dim ws As Worksheet: Set ws = wb.Sheets("Dashboard")
    Dim lr As Long: lr = wb.Sheets("Controls Library").Cells(wb.Sheets("Controls Library").Rows.Count, 1).End(xlUp).Row
    
    ws.Columns("A").ColumnWidth = 3: ws.Columns("B").ColumnWidth = 38
    ws.Columns("C").ColumnWidth = 20: ws.Columns("D").ColumnWidth = 20
    ws.Columns("E").ColumnWidth = 20: ws.Columns("F").ColumnWidth = 20: ws.Columns("G").ColumnWidth = 20
    
    ws.Range("B2:F2").Merge
    ws.Cells(2, 2).Value = "SECURITY ASSESSMENT DASHBOARD"
    ws.Cells(2, 2).Font.Name = "Arial": ws.Cells(2, 2).Font.Size = 16
    ws.Cells(2, 2).Font.Bold = True: ws.Cells(2, 2).Font.Color = RGB(27, 42, 74)
    
    ' Project summary
    Dim pLabels As Variant, pForms As Variant
    pLabels = Array("Project Name:", "Assessment Date:", "Risk Classification:", "Deployment Model:")
    pForms = Array("='Project Profile'!D6", "='Project Profile'!D9", "='Project Profile'!D15", "='Project Profile'!D13")
    Dim i As Long
    For i = 0 To 3
        ws.Cells(4 + i, 2).Value = pLabels(i): ws.Cells(4 + i, 2).Font.Bold = True: ws.Cells(4 + i, 2).Font.Name = "Arial"
        ws.Cells(4 + i, 3).Formula = pForms(i): ws.Cells(4 + i, 3).Font.Name = "Arial"
    Next i
    
    Dim r As Long
    
    ' Risk Score section
    r = 9
    ws.Range("B" & r & ":G" & r).Merge
    ws.Cells(r, 2).Value = "RISK SCORE (0 = Critical, 100 = Fully Secure)"
    ws.Cells(r, 2).Font.Name = "Arial": ws.Cells(r, 2).Font.Size = 11: ws.Cells(r, 2).Font.Bold = True
    ws.Cells(r, 2).Font.Color = RGB(255, 255, 255)
    Dim gc As Long: For gc = 2 To 7: ws.Cells(r, gc).Interior.Color = RGB(183, 28, 28): Next gc
    
    r = 10
    ws.Cells(r, 2).Value = "OVERALL RISK SCORE": ws.Cells(r, 2).Font.Name = "Arial"
    ws.Cells(r, 2).Font.Size = 14: ws.Cells(r, 2).Font.Bold = True: ws.Cells(r, 2).Borders.LineStyle = xlContinuous
    
    Dim mhP As String, allP As String, dF As String, inF As String
    mhP = "IF(COUNTIFS('Security Checklist'!G2:G" & lr & ",""MUST-HAVE"",'Security Checklist'!M2:M" & lr & _
        ",""Yes"")=0,0,COUNTIFS('Security Checklist'!G2:G" & _
        lr & _
        ",""MUST-HAVE"",'Security Checklist'!I2:I" & lr & ",""Implemented"",'Security Checklist'!M2:M" & lr & _
            ",""Yes"")/COUNTIFS('Security Checklist'!G2:G" & _
            lr & _
        ",""MUST-HAVE"",'Security Checklist'!M2:M" & lr & ",""Yes""))"
    allP = "IF(COUNTIF('Security Checklist'!M2:M" & lr & ",""Yes"")=0,0,COUNTIFS('Security Checklist'!I2:I" & lr & _
        ",""Implemented"",'Security Checklist'!M2:M" & lr & _
        ",""Yes"")/COUNTIF('Security Checklist'!M2:M" & lr & ",""Yes""))"
    dF = "IF('Project Profile'!D31=""Secret"",0.7,IF('Project Profile'!D31=""Confidential"",0.8,IF('Project Profile'!D31=""Restricted"",0.9,1)))"
    inF = "IF('Project Profile'!D42=""Yes"",0.9,1)"
    
    ws.Cells(r, 3).Formula = "=ROUND((" & mhP & "*60+" & allP & "*20+" & dF & "*10+" & inF & "*10),0)"
    ws.Cells(r, 3).Font.Name = "Arial": ws.Cells(r, 3).Font.Size = 24: ws.Cells(r, 3).Font.Bold = True
    ws.Cells(r, 3).HorizontalAlignment = xlCenter: ws.Cells(r, 3).NumberFormat = "0"
    ws.Cells(r, 3).Borders.LineStyle = xlContinuous: ws.Rows(r).RowHeight = 45
    ws.Cells(r, 3).FormatConditions.Add Type:=xlCellValue, Operator:=xlGreaterEqual, Formula1:="80"
    ws.Cells(r, 3).FormatConditions(1).Interior.Color = RGB(226, 239, 218)
    ws.Cells(r, 3).FormatConditions(1).Font.Color = RGB(46, 125, 50)
    ws.Cells(r, 3).FormatConditions.Add Type:=xlCellValue, Operator:=xlLess, Formula1:="50"
    ws.Cells(r, 3).FormatConditions(2).Interior.Color = RGB(252, 228, 236)
    ws.Cells(r, 3).FormatConditions(2).Font.Color = RGB(198, 40, 40)
    
    r = 11
    ws.Cells(r, 2).Value = "Score: 60% MUST-HAVE + 20% overall + 10% data sensitivity + 10% exposure"
    ws.Cells(r, 2).Font.Name = "Arial": ws.Cells(r, 2).Font.Size = 9: ws.Cells(r, 2).Font.Italic = True: ws.Cells(r, 2).Font.Color = RGB(128, 128, 128)
    
    ' Compliance counts
    r = 13
    ws.Range("B" & r & ":G" & r).Merge
    ws.Cells(r, 2).Value = "OVERALL COMPLIANCE SCORE"
    ws.Cells(r, 2).Font.Name = "Arial": ws.Cells(r, 2).Font.Size = 11: ws.Cells(r, 2).Font.Bold = True: ws.Cells(r, 2).Font.Color = RGB(255, 255, 255)
    For gc = 2 To 7: ws.Cells(r, gc).Interior.Color = RGB(46, 80, 144): Next gc
    
    r = 14
    Dim cLabels As Variant, cForms As Variant, cBGs As Variant
    cLabels = Array("Total Applicable Controls", "Controls Implemented", "Controls In Progress", "Controls Not Started")
    cForms = Array( _
        "=COUNTIF('Security Checklist'!M2:M" & lr & ",""Yes"")", _
        "=COUNTIFS('Security Checklist'!I2:I" & lr & ",""Implemented"",'Security Checklist'!M2:M" & lr & ",""Yes"")", _
        "=COUNTIFS('Security Checklist'!I2:I" & lr & ",""In Progress"",'Security Checklist'!M2:M" & lr & ",""Yes"")", _
        "=COUNTIFS('Security Checklist'!I2:I" & lr & ",""Not Started"",'Security Checklist'!M2:M" & lr & ",""Yes"")+COUNTIFS('Security Checklist'!I2:I" & _
            lr & _
            ","""",'Security Checklist'!M2:M" & lr & ",""Yes"")")
    cBGs = Array(RGB(214, 228, 240), RGB(226, 239, 218), RGB(255, 242, 204), RGB(252, 228, 236))
    
    For i = 0 To 3
        ws.Cells(r, 2).Value = cLabels(i): ws.Cells(r, 2).Font.Bold = True: ws.Cells(r, 2).Font.Name = "Arial"
        ws.Cells(r, 2).Borders.LineStyle = xlContinuous
        ws.Cells(r, 3).Formula = cForms(i): ws.Cells(r, 3).Font.Bold = True: ws.Cells(r, 3).Font.Name = "Arial"
        ws.Cells(r, 3).Interior.Color = cBGs(i): ws.Cells(r, 3).Borders.LineStyle = xlContinuous
        r = r + 1
    Next i
    
    ws.Cells(r, 2).Value = "COMPLIANCE PERCENTAGE": ws.Cells(r, 2).Font.Name = "Arial"
    ws.Cells(r, 2).Font.Size = 12: ws.Cells(r, 2).Font.Bold = True: ws.Cells(r, 2).Borders.LineStyle = xlContinuous
    ws.Cells(r, 3).Formula = "=IF(C14=0,0,C15/C14)": ws.Cells(r, 3).NumberFormat = "0.0%"
    ws.Cells(r, 3).Font.Name = "Arial": ws.Cells(r, 3).Font.Size = 14: ws.Cells(r, 3).Font.Bold = True
    ws.Cells(r, 3).Interior.Color = RGB(214, 228, 240): ws.Cells(r, 3).HorizontalAlignment = xlCenter
    ws.Cells(r, 3).Borders.LineStyle = xlContinuous
    ws.Cells(r, 3).FormatConditions.Add Type:=xlCellValue, Operator:=xlGreaterEqual, Formula1:="0.8"
    ws.Cells(r, 3).FormatConditions(1).Interior.Color = RGB(226, 239, 218)
    ws.Cells(r, 3).FormatConditions(1).Font.Color = RGB(46, 125, 50)
    ws.Cells(r, 3).FormatConditions.Add Type:=xlCellValue, Operator:=xlLess, Formula1:="0.5"
    ws.Cells(r, 3).FormatConditions(2).Interior.Color = RGB(252, 228, 236)
    ws.Cells(r, 3).FormatConditions(2).Font.Color = RGB(198, 40, 40)
    
    ' Domain breakdown
    r = r + 2
    ws.Range("B" & r & ":G" & r).Merge
    ws.Cells(r, 2).Value = "BREAKDOWN BY DOMAIN"
    ws.Cells(r, 2).Font.Name = "Arial": ws.Cells(r, 2).Font.Size = 11: ws.Cells(r, 2).Font.Bold = True
    ws.Cells(r, 2).Font.Color = RGB(255, 255, 255)
    For gc = 2 To 7: ws.Cells(r, gc).Interior.Color = RGB(46, 80, 144): Next gc
    
    r = r + 1
    Dim dh As Variant: dh = Array("Domain", "Applicable", "Implemented", "In Progress", "Not Started", "% Complete")
    For i = 0 To 5: ws.Cells(r, i + 2).Value = dh(i): Next i
    Call FmtHeader(ws.Range("B" & r & ":G" & r))
    
    r = r + 1
    Dim doms As Variant
    doms = Array("Info Classification", "Secure-by-Design", "Sec Hardening", "Dev Environment", _
                 "App Security", "Access Control", "Privileged Access", "MFA", "Password Mgmt", _
                 "Audit Trail", "Network Security", "Remote Access", "Firewall", "Encryption", _
                 "SaaS Security", "SaaS Data", "SaaS Assurance", "SaaS Compliance", "SaaS API Security")
    
 
    
    Dim d As Long
    For d = 0 To UBound(doms)
        ws.Cells(r, 2).Value = doms(d): ws.Cells(r, 2).Font.Name = "Arial": ws.Cells(r, 2).Font.Size = 10
        ws.Cells(r, 3).Formula = "=COUNTIFS('Security Checklist'!C2:C" & lr & ",B" & r & ",'Security Checklist'!M2:M" & lr & ",""Yes"")"
        ws.Cells(r, _
            4).Formula = "=COUNTIFS('Security Checklist'!C2:C" & lr & ",B" & r & ",'Security Checklist'!I2:I" & lr & _
                ",""Implemented"",'Security Checklist'!M2:M" & lr & _
                ",""Ye" & _
                "s"")"
        ws.Cells(r, _
            5).Formula = "=COUNTIFS('Security Checklist'!C2:C" & lr & ",B" & r & ",'Security Checklist'!I2:I" & lr & _
                ",""In Progress"",'Security Checklist'!M2:M" & lr & _
                ",""Ye" & _
                "s"")"
        ws.Cells(r, 6).Formula = "=C" & r & "-D" & r & "-E" & r
        ws.Cells(r, 7).Formula = "=IF(C" & r & "=0,""-"",D" & r & "/C" & r & ")"
        ws.Cells(r, 7).NumberFormat = "0%"
        For gc = 2 To 7
            ws.Cells(r, gc).Borders.LineStyle = xlContinuous: ws.Cells(r, gc).Font.Name = "Arial": ws.Cells(r, gc).Font.Size = 10
            If gc > 2 Then ws.Cells(r, gc).HorizontalAlignment = xlCenter
        Next gc
        If d Mod 2 = 0 Then
            For gc = 2 To 7: ws.Cells(r, gc).Interior.Color = RGB(242, 242, 242): Next gc
        End If
        r = r + 1
    Next d
    
    ' MUST-HAVE Gap
    r = r + 1
    ws.Range("B" & r & ":G" & r).Merge
    ws.Cells(r, 2).Value = "MUST-HAVE CONTROLS GAP ANALYSIS"
    ws.Cells(r, 2).Font.Name = "Arial": ws.Cells(r, 2).Font.Size = 11: ws.Cells(r, 2).Font.Bold = True: ws.Cells(r, 2).Font.Color = RGB(255, 255, 255)
    For gc = 2 To 7: ws.Cells(r, gc).Interior.Color = RGB(46, 80, 144): Next gc
    
    r = r + 1: Dim mhS As Long: mhS = r
    ws.Cells(r, 2).Value = "Total MUST-HAVE Applicable": ws.Cells(r, 2).Font.Bold = True: ws.Cells(r, 2).Font.Name = "Arial"
    ws.Cells(r, 3).Formula = "=COUNTIFS('Security Checklist'!G2:G" & lr & ",""MUST-HAVE"",'Security Checklist'!M2:M" & lr & ",""Yes"")"
    ws.Cells(r, 2).Borders.LineStyle = xlContinuous: ws.Cells(r, 3).Borders.LineStyle = xlContinuous
    
    r = r + 1
    ws.Cells(r, 2).Value = "MUST-HAVE Implemented": ws.Cells(r, 2).Font.Bold = True: ws.Cells(r, 2).Font.Name = "Arial"
    ws.Cells(r, _
        3).Formula = "=COUNTIFS('Security Checklist'!G2:G" & lr & ",""MUST-HAVE"",'Security Checklist'!I2:I" & lr & _
            ",""Implemented"",'Security Checklist'!M2:M" & lr & _
            ",""Yes" & _
            """)"
    ws.Cells(r, 3).Interior.Color = RGB(226, 239, 218)
    ws.Cells(r, 2).Borders.LineStyle = xlContinuous: ws.Cells(r, 3).Borders.LineStyle = xlContinuous
    
    r = r + 1
    ws.Cells(r, 2).Value = "MUST-HAVE Gap": ws.Cells(r, 2).Font.Bold = True: ws.Cells(r, 2).Font.Name = "Arial"
    ws.Cells(r, 2).Font.Color = RGB(198, 40, 40)
    ws.Cells(r, 3).Formula = "=C" & mhS & "-C" & mhS + 1: ws.Cells(r, 3).Font.Size = 12
    ws.Cells(r, 3).Font.Bold = True: ws.Cells(r, 3).Font.Color = RGB(198, 40, 40)
    ws.Cells(r, 3).Interior.Color = RGB(252, 228, 236)
    ws.Cells(r, 2).Borders.LineStyle = xlContinuous: ws.Cells(r, 3).Borders.LineStyle = xlContinuous
    
    r = r + 1
    ws.Cells(r, 2).Value = "MUST-HAVE Compliance %": ws.Cells(r, 2).Font.Bold = True: ws.Cells(r, 2).Font.Name = "Arial"
    ws.Cells(r, 3).Formula = "=IF(C" & mhS & "=0,0,C" & mhS + 1 & "/C" & mhS & ")"
    ws.Cells(r, 3).NumberFormat = "0.0%": ws.Cells(r, 3).Font.Size = 12: ws.Cells(r, 3).Font.Bold = True
    ws.Cells(r, 2).Borders.LineStyle = xlContinuous: ws.Cells(r, 3).Borders.LineStyle = xlContinuous
    
    r = r + 2
    ws.Cells(r, 2).Value = "Run 'ExportSummary' macro to generate a printable 1-page report."
    ws.Cells(r, 2).Font.Name = "Arial": ws.Cells(r, 2).Font.Size = 10: ws.Cells(r, 2).Font.Italic = True: ws.Cells(r, 2).Font.Color = RGB(46, 80, 144)
End Sub

' ============================================================
' ADMIN CONSOLE
' ============================================================
Sub BuildAdminConsole(wb As Workbook)
    Dim ws As Worksheet: Set ws = wb.Sheets("Admin Console")
    ws.Columns("A").ColumnWidth = 3: ws.Columns("B").ColumnWidth = 5
    ws.Columns("C").ColumnWidth = 25: ws.Columns("D").ColumnWidth = 50: ws.Columns("E").ColumnWidth = 40
    
    ws.Range("C2:E2").Merge
    ws.Cells(2, 3).Value = "ADMIN CONSOLE"
    ws.Cells(2, 3).Font.Name = "Arial": ws.Cells(2, 3).Font.Size = 16: ws.Cells(2, 3).Font.Bold = True: ws.Cells(2, 3).Font.Color = RGB(27, 42, 74)
    ws.Range("C3:E3").Merge
    ws.Cells(3, 3).Value = "Add controls and manage settings (password required)"
    ws.Cells(3, 3).Font.Name = "Arial": ws.Cells(3, 3).Font.Size = 10: ws.Cells(3, 3).Font.Italic = True: ws.Cells(3, 3).Font.Color = RGB(74, 20, 140)
    
    Dim r As Long: r = 5
    ws.Range("C" & r & ":E" & r).Merge
    ws.Cells(r, 3).Value = "ADD NEW CONTROL"
    ws.Cells(r, 3).Font.Name = "Arial": ws.Cells(r, 3).Font.Size = 11: ws.Cells(r, 3).Font.Bold = True: ws.Cells(r, 3).Font.Color = RGB(255, 255, 255)
    Dim gc As Long: For gc = 3 To 5: ws.Cells(r, gc).Interior.Color = RGB(74, 20, 140): Next gc
    
    r = 6
    Dim fields As Variant, hints As Variant
    fields = Array("Control ID", "Domain", "Sub-Domain", "Control Description", "Implementation Guidance", "Verification Method", "Applicable Components", _
        "Trigger Condition", _
        "Priority", "Source Reference", "Enabled")
    hints = Array("e.g. CUSTOM-001", "e.g. App Security", "e.g. Authentication", "Full description", "Steps to implement", "How to verify", "All," & _
        "Web Application, etc.", _
        "ALWAYS," & _
        "Deployment=SaaS, etc.", "MUST-HAVE/SHOULD-HAVE/NICE-TO-HAVE", "e.g. Std 7.2.2", "Yes or No")
    
    Dim fi As Long
    For fi = 0 To UBound(fields)
        ws.Cells(r, 3).Value = fields(fi): ws.Cells(r, 3).Font.Name = "Arial": ws.Cells(r, 3).Font.Bold = True
        ws.Cells(r, 3).Borders.LineStyle = xlContinuous
        ws.Cells(r, 4).Interior.Color = RGB(232, 213, 245): ws.Cells(r, 4).Borders.LineStyle = xlContinuous
        ws.Cells(r, 4).Locked = False
        ws.Cells(r, 5).Value = hints(fi): ws.Cells(r, 5).Font.Name = "Arial": ws.Cells(r, 5).Font.Size = 9
        ws.Cells(r, 5).Font.Italic = True: ws.Cells(r, 5).Font.Color = RGB(128, 128, 128)
        r = r + 1
    Next fi
    
    ' Dropdowns for priority and enabled
    With ws.Cells(14, 4).Validation: .Delete: .Add Type:=xlValidateList, Formula1:="=Lookups!$E$2:$E$4": End With
    With ws.Cells(16, 4).Validation: .Delete: .Add Type:=xlValidateList, Formula1:="=Lookups!$M$2:$M$3": End With
    
    r = r + 1
    ws.Cells(r, 3).Value = "Run macro 'AddControlFromConsole' to add the control above."
    ws.Cells(r, 3).Font.Name = "Arial": ws.Cells(r, 3).Font.Size = 10: ws.Cells(r, 3).Font.Bold = True: ws.Cells(r, 3).Font.Color = RGB(74, 20, 140)
    r = r + 2
    
    Dim instrLines As Variant
    instrLines = Array("TRIGGER CONDITION REFERENCE:", "  ALWAYS = applies to every project", "  Deployment!=SaaS = not SaaS", _
        "  Deployment=SaaS = SaaS only", "  DataClass=Confidential OR DataClass=Secret", "  InternetFacing=Yes / InternetFacing=No", _
        "  PrivAccounts=Yes / RemoteAccess=Yes / FileTransfer=Yes / PaymentData=Yes", _
        "  AppArch=3-Tier OR AppArch=N-Tier", "", "AVAILABLE MACROS:", _
        "  RefreshChecklist - Filter to show only applicable controls", _
        "  ShowAllControls - Clear all filters", _
        "  ExportSummary - Generate 1-page executive summary", _
        "  AddControlFromConsole - Add control from fields above", _
        "  UnlockForAdmin - Unlock all sheets (password required)", _
        "  LockAllSheets - Re-lock all sheets")
    
    Dim li As Long
    For li = 0 To UBound(instrLines)
        ws.Cells(r, 3).Value = instrLines(li): ws.Cells(r, 3).Font.Name = "Arial": ws.Cells(r, 3).Font.Size = 9
        r = r + 1
    Next li
End Sub

' ============================================================
' CHANGE LOG
' ============================================================
Sub BuildChangeLog(wb As Workbook)
    Dim ws As Worksheet: Set ws = wb.Sheets("Change Log")
    Dim h As Variant: h = Array("#", "Date/Time", "Action", "Control ID", "Field Changed", "Old Value", "New Value", "Changed By")
    Dim w As Variant: w = Array(5, 20, 20, 12, 20, 30, 30, 15)
    Dim i As Long
    For i = 0 To 7: ws.Cells(1, i + 1).Value = h(i): ws.Columns(i + 1).ColumnWidth = w(i): Next i
    Call FmtHeader(ws.Range("A1:H1"))
    ws.Cells(2, 1).Value = 1: ws.Cells(2, 2).Value = Format(Now, "yyyy-mm-dd hh:mm:ss")
    ws.Cells(2, 3).Value = "Initial Build": ws.Cells(2, 4).Value = "ALL"
    ws.Cells(2, 5).Value = "N/A": ws.Cells(2, 6).Value = "N/A"
    ws.Cells(2, 7).Value = "124 controls loaded": ws.Cells(2, 8).Value = "System"
    Dim c As Long
    For c = 1 To 8: ws.Cells(2, c).Font.Name = "Arial": ws.Cells(2, c).Font.Size = 10: ws.Cells(2, c).Borders.LineStyle = xlContinuous: Next c
End Sub

' ============================================================
' INSTRUCTIONS
' ============================================================
Sub BuildInstructions(wb As Workbook)
    Dim ws As Worksheet: Set ws = wb.Sheets("Instructions")
    ws.Columns("A").ColumnWidth = 5: ws.Columns("B").ColumnWidth = 90
    
    ws.Cells(2, 2).Value = "SECURITY CONTROLS ASSESSMENT TOOL"
    ws.Cells(2, 2).Font.Name = "Arial": ws.Cells(2, 2).Font.Size = 16: ws.Cells(2, 2).Font.Bold = True: ws.Cells(2, 2).Font.Color = RGB(27, 42, 74)
    ws.Cells(3, 2).Value = "Intelligent Project Security Review Tool v3.0 (124 controls)"
    ws.Cells(3, 2).Font.Name = "Arial": ws.Cells(3, 2).Font.Size = 12: ws.Cells(3, 2).Font.Bold = True: ws.Cells(3, 2).Font.Color = RGB(46, 80, 144)
    
    Dim r As Long: r = 5
    Call WriteInstrLine(ws, r, "~PURPOSE", True)
    Call WriteInstrLine(ws, r, "Simplifies 124 security controls into a customized checklist based on your project profile.", False)
    Call WriteInstrLine(ws, r, "", False)
    Call WriteInstrLine(ws, r, "~HOW TO USE", True)
    Call WriteInstrLine(ws, r, "STEP 1: Go to Project Profile and fill in ALL yellow cells.", False)
    Call WriteInstrLine(ws, r, "STEP 2: Run RefreshChecklist macro to filter applicable controls.", False)
    Call WriteInstrLine(ws, r, "STEP 3: Review Dashboard for risk score and gap analysis.", False)
    Call WriteInstrLine(ws, r, "STEP 4: Update Status column for each control in Security Checklist.", False)
    Call WriteInstrLine(ws, r, "STEP 5: Run ExportSummary macro for a printable 1-page report.", False)
    Call WriteInstrLine(ws, r, "", False)
    Call WriteInstrLine(ws, r, "~ADMIN FEATURES (Password: " & ADMIN_PWD & ")", True)
    Call WriteInstrLine(ws, r, "All sheets are LOCKED. Users can only edit yellow input cells.", False)
    Call WriteInstrLine(ws, r, "Run UnlockForAdmin to unlock. Run LockAllSheets to re-lock.", False)
    Call WriteInstrLine(ws, r, "Controls Library Column K (Enabled) is the master switch.", False)
    Call WriteInstrLine(ws, r, "Admin Console provides guided interface to add new controls.", False)
    Call WriteInstrLine(ws, r, "Change Log (hidden) auto-records all admin actions.", False)
    Call WriteInstrLine(ws, r, "", False)
    Call WriteInstrLine(ws, r, "~SHEETS", True)
    Call WriteInstrLine(ws, r, "Instructions - This page", False)
    Call WriteInstrLine(ws, r, "Project Profile - INPUT: Architecture, data, compliance", False)
    Call WriteInstrLine(ws, r, "Controls Library - REFERENCE: 124 controls with Enabled toggle", False)
    Call WriteInstrLine(ws, r, "Security Checklist - OUTPUT: Auto-filtered checklist", False)
    Call WriteInstrLine(ws, r, "Dashboard - OUTPUT: Risk score, compliance %, gap analysis", False)
    Call WriteInstrLine(ws, r, "Admin Console - ADMIN: Add controls via guided form", False)
    Call WriteInstrLine(ws, r, "Change Log - AUDIT: Hidden log of admin changes", False)
    Call WriteInstrLine(ws, r, "Lookups - SYSTEM: Dropdown source lists", False)
End Sub

' ============================================================

Sub WriteInstrLine(ws As Worksheet, r As Long, txt As String, isHeader As Boolean)
    ws.Cells(r, 2).WrapText = True
    If isHeader And Left(txt, 1) = "~" Then
        ws.Cells(r, 2).Value = Mid(txt, 2)
        ws.Cells(r, 2).Font.Name = "Arial"
        ws.Cells(r, 2).Font.Size = 11
        ws.Cells(r, 2).Font.Bold = True
        ws.Cells(r, 2).Font.Color = RGB(46, 80, 144)
    Else
        ws.Cells(r, 2).Value = txt
        ws.Cells(r, 2).Font.Name = "Arial"
        ws.Cells(r, 2).Font.Size = 10
    End If
    r = r + 1
End Sub

' OPERATIONAL MACROS (use after tool is built)
' ============================================================

Sub UnlockForAdmin()
    Dim pw As String: pw = InputBox("Enter admin password:", "Admin Unlock")
    If pw <> ADMIN_PWD Then MsgBox "Incorrect password.", vbCritical: Exit Sub
    Dim ws As Worksheet
    For Each ws In ActiveWorkbook.Sheets
        On Error Resume Next: ws.Unprotect Password:=ADMIN_PWD: On Error GoTo 0
    Next ws
    ActiveWorkbook.Sheets("Change Log").Visible = xlSheetVisible
    MsgBox "All sheets unlocked. Run 'LockAllSheets' when done.", vbInformation
End Sub

Sub LockAllSheets()
    Dim ws As Worksheet
    For Each ws In ActiveWorkbook.Sheets
        If ws.Name = "Security Checklist" Then
            ws.Protect Password:=ADMIN_PWD, AllowFiltering:=True, AllowSorting:=True
        Else
            ws.Protect Password:=ADMIN_PWD
        End If
    Next ws
    On Error Resume Next
    ActiveWorkbook.Sheets("Change Log").Visible = xlSheetHidden
    On Error GoTo 0
    MsgBox "All sheets locked.", vbInformation
End Sub

Sub LogChange(action As String, ctrlID As String, field As String, oldVal As String, newVal As String)
    Dim wsLog As Worksheet
    On Error Resume Next
    Set wsLog = ActiveWorkbook.Sheets("Change Log")
    wsLog.Visible = xlSheetVisible: wsLog.Unprotect Password:=ADMIN_PWD
    On Error GoTo 0
    If wsLog Is Nothing Then Exit Sub
    Dim nr As Long: nr = wsLog.Cells(wsLog.Rows.Count, 1).End(xlUp).Row + 1
    wsLog.Cells(nr, 1).Value = nr - 1
    wsLog.Cells(nr, 2).Value = Format(Now, "yyyy-mm-dd hh:mm:ss")
    wsLog.Cells(nr, 3).Value = action: wsLog.Cells(nr, 4).Value = ctrlID
    wsLog.Cells(nr, 5).Value = field: wsLog.Cells(nr, 6).Value = oldVal
    wsLog.Cells(nr, 7).Value = newVal: wsLog.Cells(nr, 8).Value = Environ("USERNAME")
    Dim c As Long
    For c = 1 To 8: wsLog.Cells(nr, c).Font.Name = "Arial": wsLog.Cells(nr, c).Font.Size = 10: wsLog.Cells(nr, c).Borders.LineStyle = xlContinuous: Next c
    wsLog.Protect Password:=ADMIN_PWD: wsLog.Visible = xlSheetHidden
End Sub

Sub RefreshChecklist()
    Dim ws As Worksheet: Set ws = ActiveWorkbook.Sheets("Security Checklist")
    Application.Calculate
    If ws.AutoFilterMode Then ws.AutoFilter.ShowAllData
    Dim lr As Long: lr = ws.Cells(ws.Rows.Count, 2).End(xlUp).Row
    If Not ws.AutoFilterMode Then ws.Range("A1:M" & lr).AutoFilter
    ws.Range("A1:M" & lr).AutoFilter field:=13, Criteria1:="Yes"
    ws.Range("A1:M" & lr).AutoFilter field:=12, Criteria1:="Yes"
    ws.Activate: ws.Range("A1").Select
    MsgBox "Showing only applicable and enabled controls." & vbCrLf & "To see all: run 'ShowAllControls'.", vbInformation
End Sub

Sub ShowAllControls()
    Dim ws As Worksheet: Set ws = ActiveWorkbook.Sheets("Security Checklist")
    If ws.AutoFilterMode Then ws.AutoFilter.ShowAllData
    ws.Activate
    MsgBox "All filters cleared. Showing all " & ws.Cells(ws.Rows.Count, 2).End(xlUp).Row - 1 & " controls.", vbInformation
End Sub

Sub ExportSummary()
    Dim wb As Workbook: Set wb = ActiveWorkbook
    Dim wsDash As Worksheet: Set wsDash = wb.Sheets("Dashboard")
    Dim wsChk As Worksheet: Set wsChk = wb.Sheets("Security Checklist")
    Application.DisplayAlerts = False
    On Error Resume Next: wb.Sheets("Executive Summary").Delete: On Error GoTo 0
    Application.DisplayAlerts = True
    Dim ws As Worksheet: Set ws = wb.Sheets.Add(After:=wb.Sheets("Dashboard"))
    ws.Name = "Executive Summary": ws.Tab.Color = RGB(27, 42, 74)
    With ws.PageSetup: .Orientation = xlPortrait: .PaperSize = xlPaperA4: .FitToPagesWide = 1: .FitToPagesTall = 1: End With
    ws.Columns("A").ColumnWidth = 3: ws.Columns("B").ColumnWidth = 28: ws.Columns("C").ColumnWidth = 15
    ws.Columns("D").ColumnWidth = 15: ws.Columns("E").ColumnWidth = 15: ws.Columns("F").ColumnWidth = 15
    Dim r As Long: r = 2
    ws.Range("B" & r & ":F" & r).Merge: ws.Cells(r, 2).Value = "SECURITY ASSESSMENT - EXECUTIVE SUMMARY"
    ws.Cells(r, 2).Font.Name = "Arial": ws.Cells(r, 2).Font.Size = 16: ws.Cells(r, 2).Font.Bold = True: ws.Cells(r, 2).Font.Color = RGB(27, 42, 74)
    r = 3: ws.Range("B" & r & ":F" & r).Borders(xlEdgeBottom).LineStyle = xlContinuous
    r = 5
    Dim pl As Variant, pv As Variant: pl = Array("Project:", "Date:", "Risk:", "Deployment:")
    pv = Array(4, 5, 6, 7)
    Dim i As Long
    For i = 0 To 3: ws.Cells(r, 2).Value = pl(i): ws.Cells(r, 2).Font.Bold = True: ws.Cells(r, 3).Value = wsDash.Cells(pv(i), 3).Value: r = r + 1: Next i
    r = r + 1: ws.Cells(r, 2).Value = "RISK SCORE": ws.Cells(r, 2).Font.Size = 12: ws.Cells(r, 2).Font.Bold = True
    Dim sc As Variant: sc = wsDash.Cells(10, 3).Value
    ws.Cells(r, 4).Value = sc: ws.Cells(r, 4).Font.Size = 20: ws.Cells(r, 4).Font.Bold = True
    ws.Cells(r, 4).HorizontalAlignment = xlCenter: ws.Cells(r, 4).NumberFormat = "0": ws.Cells(r, 4).Borders.LineStyle = xlContinuous
    If IsNumeric(sc) Then
        If sc >= 80 Then ws.Cells(r, 4).Interior.Color = RGB(226, 239, 218): ws.Cells(r, 4).Font.Color = RGB(46, 125, 50)
        If sc < 50 Then ws.Cells(r, 4).Interior.Color = RGB(252, 228, 236): ws.Cells(r, 4).Font.Color = RGB(198, 40, 40)
        If sc >= 50 And sc < 80 Then ws.Cells(r, 4).Interior.Color = RGB(255, 242, 204): ws.Cells(r, 4).Font.Color = RGB(230, 81, 0)
    End If
    ws.Cells(r, 5).Value = "/ 100"
    r = r + 2: ws.Cells(r, 2).Value = "Compliance": ws.Cells(r, 2).Font.Bold = True: ws.Cells(r, 2).Font.Size = 12: r = r + 1
    Dim sl As Variant, sr As Variant: sl = Array("Applicable", "Implemented", "In Progress", "Not Started", "Compliance %")
    sr = Array(14, 15, 16, 17, 18)
    For i = 0 To 4
        ws.Cells(r, 2).Value = sl(i): ws.Cells(r, 3).Value = wsDash.Cells(sr(i), 3).Value
        If i = 4 Then ws.Cells(r, 3).NumberFormat = "0.0%"
        ws.Cells(r, 2).Borders.LineStyle = xlContinuous: ws.Cells(r, 3).Borders.LineStyle = xlContinuous
        ws.Cells(r, 3).HorizontalAlignment = xlCenter: r = r + 1
    Next i
    r = r + 1: ws.Cells(r, 2).Value = "TOP GAPS (MUST-HAVE Not Implemented)"
    ws.Cells(r, 2).Font.Bold = True: ws.Cells(r, 2).Font.Size = 12: ws.Cells(r, 2).Font.Color = RGB(198, 40, 40): r = r + 1
    ws.Cells(r, 2).Value = "Control ID": ws.Cells(r, 3).Value = "Domain": ws.Range("D" & r & ":F" & r).Merge: ws.Cells(r, 4).Value = "Description"
    Dim hc As Long: For hc = 2 To 6: ws.Cells(r, hc).Font.Bold = True: ws.Cells(r, hc).Font.Color = RGB(255, 255, 255): ws.Cells(r, _
        hc).Interior.Color = RGB(27, 42, _
        74): ws.Cells(r, hc).Borders.LineStyle = xlContinuous: Next hc
    r = r + 1: Dim lc As Long, gc As Long: lc = wsChk.Cells(wsChk.Rows.Count, 2).End(xlUp).Row: gc = 0
    Dim cr As Long
    For cr = 2 To lc
        If gc >= 5 Then Exit For
        If wsChk.Cells(cr, 7).Value = "MUST-HAVE" And wsChk.Cells(cr, 13).Value = "Yes" And (wsChk.Cells(cr, 9).Value = "" Or wsChk.Cells(cr, _
            9).Value = "Not Started") Then
            ws.Cells(r, 2).Value = wsChk.Cells(cr, 2).Value: ws.Cells(r, 3).Value = wsChk.Cells(cr, 3).Value
            ws.Range("D" & r & ":F" & r).Merge: ws.Cells(r, 4).Value = Left(wsChk.Cells(cr, 4).Value, 80): ws.Cells(r, 4).WrapText = True
            Dim fc As Long: For fc = 2 To 4: ws.Cells(r, fc).Borders.LineStyle = xlContinuous: ws.Cells(r, fc).Font.Size = 9: Next fc
            r = r + 1: gc = gc + 1
        End If
    Next cr
    If gc = 0 Then ws.Cells(r, 2).Value = "All MUST-HAVE controls implemented.": ws.Cells(r, 2).Font.Color = RGB(46, 125, 50): r = r + 1
    r = r + 2: ws.Range("B" & r & ":F" & r).Borders(xlEdgeTop).LineStyle = xlContinuous: r = r + 1
    ws.Cells(r, 2).Value = "SIGN-OFF": ws.Cells(r, 2).Font.Bold = True: ws.Cells(r, 2).Font.Size = 12: r = r + 2
    Dim sf As Variant: sf = Array("Project Owner", "Security Reviewer", "CISO / Delegate")
    For i = 0 To 2
        ws.Cells(r, 2).Value = sf(i) & ":": ws.Cells(r, 2).Font.Bold = True
        ws.Range("C" & r & ":D" & r).Merge: ws.Range("C" & r & ":D" & r).Borders(xlEdgeBottom).LineStyle = xlContinuous
        ws.Cells(r, 5).Value = "Date:": ws.Cells(r, 5).Font.Bold = True: ws.Cells(r, 6).Borders(xlEdgeBottom).LineStyle = xlContinuous
        r = r + 2
    Next i
    ws.PageSetup.PrintArea = "A1:F" & r: ws.Range("A1:F" & r).Font.Name = "Arial": ws.Activate
    MsgBox "Executive Summary generated! Print from File > Print.", vbInformation
End Sub

Sub AddControlFromConsole()
    Dim wb As Workbook: Set wb = ActiveWorkbook
    Dim wsA As Worksheet: Set wsA = wb.Sheets("Admin Console")
    Dim wsC As Worksheet: Set wsC = wb.Sheets("Controls Library")
    Dim wsK As Worksheet: Set wsK = wb.Sheets("Security Checklist")
    If Trim(wsA.Cells(6, 4).Value) = "" Or Trim(wsA.Cells(9, 4).Value) = "" Then
        MsgBox "Fill in Control ID and Description.", vbExclamation: Exit Sub
    End If
    On Error Resume Next: wsC.Unprotect Password:=ADMIN_PWD: wsK.Unprotect Password:=ADMIN_PWD: On Error GoTo 0
    Dim nr As Long: nr = wsC.Cells(wsC.Rows.Count, 1).End(xlUp).Row + 1
    wsC.Cells(nr, 1).Value = wsA.Cells(6, 4).Value: wsC.Cells(nr, 2).Value = wsA.Cells(7, 4).Value
    wsC.Cells(nr, 3).Value = wsA.Cells(8, 4).Value: wsC.Cells(nr, 4).Value = wsA.Cells(9, 4).Value
    wsC.Cells(nr, 5).Value = wsA.Cells(10, 4).Value: wsC.Cells(nr, 6).Value = wsA.Cells(11, 4).Value
    wsC.Cells(nr, 7).Value = wsA.Cells(12, 4).Value: wsC.Cells(nr, 8).Value = wsA.Cells(13, 4).Value
    wsC.Cells(nr, 9).Value = wsA.Cells(14, 4).Value: wsC.Cells(nr, 10).Value = wsA.Cells(15, 4).Value
    wsC.Cells(nr, 11).Value = IIf(wsA.Cells(16, 4).Value = "", "Yes", wsA.Cells(16, 4).Value)
    Dim c As Long
    For c = 1 To 11: wsC.Cells(nr, c).Font.Name = "Arial": wsC.Cells(nr, c).Font.Size = 10: wsC.Cells(nr, c).Borders.LineStyle = xlContinuous: Next c
    Dim kr As Long: kr = wsK.Cells(wsK.Rows.Count, 2).End(xlUp).Row + 1
    wsK.Cells(kr, 1).Value = kr - 1: wsK.Cells(kr, 2).Value = wsA.Cells(6, 4).Value
    wsK.Cells(kr, 3).Value = wsA.Cells(7, 4).Value: wsK.Cells(kr, 4).Value = wsA.Cells(9, 4).Value
    wsK.Cells(kr, 5).Value = wsA.Cells(10, 4).Value: wsK.Cells(kr, 6).Value = wsA.Cells(12, 4).Value
    wsK.Cells(kr, 7).Value = wsA.Cells(14, 4).Value: wsK.Cells(kr, 8).Value = wsA.Cells(11, 4).Value
    wsK.Cells(kr, 9).Interior.Color = RGB(255, 242, 204): wsK.Cells(kr, 10).Interior.Color = RGB(255, 242, 204)
    wsK.Cells(kr, 11).Value = wsA.Cells(15, 4).Value: wsK.Cells(kr, 12).Formula = "='Controls Library'!K" & nr
    Dim trig As String: trig = Trim(wsA.Cells(13, 4).Value)
    wsK.Cells(kr, 13).Formula = GetAppFormula(trig, kr)
    For c = 1 To 13: wsK.Cells(kr, c).Font.Name = "Arial": wsK.Cells(kr, c).Font.Size = 10: wsK.Cells(kr, _
        c).Borders.LineStyle = xlContinuous: wsK.Cells(kr, _
        c).WrapText = True: Next c
    With wsK.Cells(kr, 9).Validation: .Delete: .Add Type:=xlValidateList, AlertStyle:=xlValidAlertStop, Formula1:="=Lookups!$F$2:$F$5": End With
    Call LogChange("Control Added", CStr(wsA.Cells(6, 4).Value), "N/A", "N/A", "New control added")
    Dim cl As Long: For cl = 6 To 16: wsA.Cells(cl, 4).Value = "": Next cl
    wsC.Protect Password:=ADMIN_PWD: wsK.Protect Password:=ADMIN_PWD, AllowFiltering:=True, AllowSorting:=True
    MsgBox "Control added! Library row " & nr & ", Checklist row " & kr, vbInformation
End Sub



