import ipaddress
import re
import sys

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
	QApplication,
	QCheckBox,
	QComboBox,
	QFormLayout,
	QFileDialog,
	QHeaderView,
	QHBoxLayout,
	QLabel,
	QLineEdit,
	QMainWindow,
	QPlainTextEdit,
	QPushButton,
	QTabWidget,
	QTableWidget,
	QTableWidgetItem,
	QVBoxLayout,
	QWidget,
)


MODULE_TYPES = {
	"Exploit": "exploit",
	"Payload": "payload",
	"Auxiliary": "auxiliary",
	"Post": "post",
}
LOCAL_SCAN_NETWORKS = tuple(
	ipaddress.ip_network(network)
	for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")
)


class MainWindow(QMainWindow):
	def __init__(self):
		super().__init__()
		self.setWindowTitle("Security Analyst Workbench")
		self.resize(980, 720)
		self.setMinimumSize(760, 600)
		self.findings = []

		self.setStyleSheet(
			"""
			QMainWindow, QWidget {
				background: #111416;
				color: #e5e9e7;
				font-family: "Segoe UI", sans-serif;
				font-size: 10pt;
			}
			QLabel#eyebrow {
				color: #b8f36a;
				font-size: 9pt;
				font-weight: 700;
			}
			QLabel#title {
				font-size: 20pt;
				font-weight: 700;
				color: #f2f5f2;
			}
			QLabel#subtitle, QLabel#hint {
				color: #89938f;
			}
			QTabWidget::pane {
				border: 1px solid #2b3231;
				background: #151a1b;
			}
			QTabBar::tab {
				background: #111416;
				color: #89938f;
				padding: 12px 20px;
				border-bottom: 2px solid transparent;
			}
			QTabBar::tab:selected {
				color: #e5e9e7;
				border-bottom: 2px solid #b8f36a;
			}
			QLineEdit, QComboBox {
				background: #0e1112;
				color: #f2f5f2;
				border: 1px solid #343c3a;
				border-radius: 5px;
				padding: 10px 11px;
			}
			QLineEdit:focus, QComboBox:focus {
				border: 1px solid #91c64d;
			}
			QComboBox QAbstractItemView {
				background: #171d1b;
				color: #e5e9e7;
				selection-background-color: #34472b;
			}
			QPushButton {
				background: #242c2a;
				color: #e5e9e7;
				border: 1px solid #3b4642;
				border-radius: 5px;
				padding: 10px 16px;
				font-weight: 600;
			}
			QPushButton:hover {
				background: #303b36;
			}
			QPushButton#primaryButton {
				background: #b8f36a;
				color: #17200f;
				border: none;
			}
			QPushButton#primaryButton:hover {
				background: #c8ff7d;
			}
			QPlainTextEdit {
				background: #0b0e0f;
				color: #b9c5bd;
				border: 1px solid #2c3531;
				border-radius: 5px;
				padding: 10px;
				font-family: Consolas, monospace;
				font-size: 9pt;
			}
			QTableWidget {
				background: #0e1112;
				color: #e5e9e7;
				border: 1px solid #343c3a;
				gridline-color: #252c29;
				selection-background-color: #34472b;
				selection-color: #f2f5f2;
				alternate-background-color: #141918;
			}
			QHeaderView::section {
				background: #1a201e;
				color: #aeb9b2;
				padding: 8px;
				border: none;
				border-bottom: 1px solid #343c3a;
				font-weight: 700;
			}
			"""
		)

		root = QWidget()
		root_layout = QVBoxLayout(root)
		root_layout.setContentsMargins(28, 24, 28, 26)
		root_layout.setSpacing(20)

		header = QVBoxLayout()
		eyebrow = QLabel("COMMUNITY SECURITY WORKSPACE")
		eyebrow.setObjectName("eyebrow")
		title = QLabel("Security Analyst Workbench")
		title.setObjectName("title")
		subtitle = QLabel(
			"Prepare console inspection commands and document authorized assessment findings."
		)
		subtitle.setObjectName("subtitle")
		header.addWidget(eyebrow)
		header.addWidget(title)
		header.addWidget(subtitle)
		root_layout.addLayout(header)

		self.tabs = QTabWidget()
		self.tabs.addTab(self._build_instructor_tab(), "Command Instructor")
		self.tabs.addTab(self._build_defensive_pad_tab(), "Defensive Check Pad")
		self.tabs.addTab(self._build_reference_tab(), "Console Reference")
		self.tabs.addTab(self._build_report_tab(), "Assessment Report")
		root_layout.addWidget(self.tabs, 1)
		self.setCentralWidget(root)

	def _build_instructor_tab(self):
		page = QWidget()
		layout = QVBoxLayout(page)
		layout.setContentsMargins(24, 22, 24, 22)
		layout.setSpacing(14)

		heading = QLabel("Build a console command")
		heading.setStyleSheet("font-size: 15pt; font-weight: 700; color: #f2f5f2;")
		instructions = QLabel(
			"Choose a read-only catalog or module-inspection action. Nothing is executed by this app."
		)
		instructions.setObjectName("hint")
		instructions.setWordWrap(True)
		layout.addWidget(heading)
		layout.addWidget(instructions)

		form = QFormLayout()
		form.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)
		form.setHorizontalSpacing(18)
		form.setVerticalSpacing(12)
		self.module_type = QComboBox()
		self.module_type.addItems(MODULE_TYPES)
		self.search_input = QLineEdit()
		self.search_input.setPlaceholderText("Optional search term, e.g. http")
		self.module_path_input = QLineEdit()
		self.module_path_input.setPlaceholderText("e.g. auxiliary/scanner/http/title")
		form.addRow("MODULE TYPE", self.module_type)
		form.addRow("SEARCH TERM", self.search_input)
		form.addRow("MODULE PATH", self.module_path_input)
		layout.addLayout(form)

		buttons = QHBoxLayout()
		self.search_button = QPushButton("Build Search")
		self.search_button.clicked.connect(self.build_search_command)
		self.info_button = QPushButton("Build Module Info")
		self.info_button.clicked.connect(self.build_info_command)
		self.options_button = QPushButton("Build Show Options")
		self.options_button.setObjectName("primaryButton")
		self.options_button.clicked.connect(self.build_options_command)
		buttons.addWidget(self.search_button)
		buttons.addWidget(self.info_button)
		buttons.addWidget(self.options_button)
		layout.addLayout(buttons)

		command_heading = QLabel("COMMAND TO PASTE INTO MSFCONSOLE")
		command_heading.setObjectName("eyebrow")
		layout.addWidget(command_heading)
		self.command_output = QPlainTextEdit()
		self.command_output.setReadOnly(True)
		self.command_output.setPlaceholderText("Generated commands appear here.")
		self.command_output.setMaximumBlockCount(100)
		layout.addWidget(self.command_output, 1)

		command_actions = QHBoxLayout()
		self.command_status = QLabel("Not connected to or controlling msfconsole")
		self.command_status.setObjectName("hint")
		command_actions.addWidget(self.command_status)
		command_actions.addStretch(1)
		self.copy_button = QPushButton("Copy Command")
		self.copy_button.clicked.connect(self.copy_command)
		self.clear_button = QPushButton("Clear Output")
		self.clear_button.clicked.connect(self.clear_console_output)
		command_actions.addWidget(self.copy_button)
		command_actions.addWidget(self.clear_button)
		layout.addLayout(command_actions)

		output_heading = QLabel("PASTED CONSOLE OUTPUT")
		output_heading.setObjectName("eyebrow")
		layout.addWidget(output_heading)
		self.console_output = QPlainTextEdit()
		self.console_output.setPlaceholderText(
			"Paste the result from your local msfconsole here for reference."
		)
		self.console_output.setMaximumHeight(130)
		layout.addWidget(self.console_output)
		return page

	def _build_reference_tab(self):
		page = QWidget()
		layout = QVBoxLayout(page)
		layout.setContentsMargins(24, 22, 24, 22)
		layout.setSpacing(12)
		heading = QLabel("Local console workflow")
		heading.setStyleSheet("font-size: 15pt; font-weight: 700; color: #f2f5f2;")
		body = QLabel(
			"1. Start Metasploit in a terminal with: msfconsole\n\n"
			"2. Use Command Instructor to build a search or inspection command.\n\n"
			"3. Copy the generated text and paste it into the local msfconsole.\n\n"
			"4. Review the result in the terminal. Paste output into the instructor if you "
			"want to keep it visible alongside the generated command.\n\n"
			"This app is intentionally offline: it does not connect to RPC, start processes, "
			"run modules, or capture console output."
		)
		body.setObjectName("subtitle")
		body.setWordWrap(True)
		body.setTextFormat(Qt.TextFormat.PlainText)
		layout.addWidget(heading)
		layout.addWidget(body)
		layout.addStretch(1)
		return page

	def _build_defensive_pad_tab(self):
		page = QWidget()
		layout = QVBoxLayout(page)
		layout.setContentsMargins(24, 22, 24, 22)
		layout.setSpacing(14)

		heading = QLabel("Defensive check pad")
		heading.setStyleSheet("font-size: 15pt; font-weight: 700; color: #f2f5f2;")
		intro = QLabel(
			"Prepare fixed, non-exploit inventory checks for a local lab or private network. "
			"Commands are displayed for review and are never run by this app."
		)
		intro.setObjectName("hint")
		intro.setWordWrap(True)
		layout.addWidget(heading)
		layout.addWidget(intro)

		form = QFormLayout()
		form.setHorizontalSpacing(18)
		form.setVerticalSpacing(10)
		self.scan_target_input = QLineEdit()
		self.scan_target_input.setPlaceholderText("e.g. 192.168.1.25 or 192.168.1.0/24")
		form.addRow("LAB TARGET", self.scan_target_input)
		layout.addLayout(form)

		self.scan_authorization = QCheckBox(
			"I am authorized to assess this target and it is within the scope I documented."
		)
		layout.addWidget(self.scan_authorization)

		checks = QHBoxLayout()
		self.port_inventory_button = QPushButton("Prepare TCP Service Inventory")
		self.port_inventory_button.clicked.connect(
			lambda: self.prepare_defensive_check("ports")
		)
		self.http_inventory_button = QPushButton("Prepare HTTP Title Check")
		self.http_inventory_button.setObjectName("primaryButton")
		self.http_inventory_button.clicked.connect(
			lambda: self.prepare_defensive_check("http")
		)
		checks.addWidget(self.port_inventory_button)
		checks.addWidget(self.http_inventory_button)
		layout.addLayout(checks)

		self.scan_status = QLabel(
			"Allowed scope: loopback or RFC1918 IPv4; maximum 256 addresses."
		)
		self.scan_status.setObjectName("hint")
		self.scan_status.setWordWrap(True)
		layout.addWidget(self.scan_status)

		command_heading = QLabel("PREPARED MSFCONSOLE COMMANDS")
		command_heading.setObjectName("eyebrow")
		layout.addWidget(command_heading)
		self.scan_command_output = QPlainTextEdit()
		self.scan_command_output.setReadOnly(True)
		self.scan_command_output.setPlaceholderText(
			"Choose an inventory check after confirming the target scope."
		)
		layout.addWidget(self.scan_command_output, 1)

		actions = QHBoxLayout()
		actions.addStretch(1)
		self.copy_scan_command_button = QPushButton("Copy Commands")
		self.copy_scan_command_button.clicked.connect(self.copy_scan_commands)
		self.clear_scan_command_button = QPushButton("Clear")
		self.clear_scan_command_button.clicked.connect(self.scan_command_output.clear)
		actions.addWidget(self.copy_scan_command_button)
		actions.addWidget(self.clear_scan_command_button)
		layout.addLayout(actions)
		return page

	def validated_scan_target(self):
		target_text = self.scan_target_input.text().strip()
		try:
			network = ipaddress.ip_network(
				target_text if "/" in target_text else f"{target_text}/32",
				strict=False,
			)
		except ValueError:
			self.scan_status.setText("Enter a valid IPv4 address or CIDR range.")
			return None

		if network.version != 4:
			self.scan_status.setText("Only IPv4 targets are supported in this check pad.")
			return None
		if not any(network.subnet_of(allowed) for allowed in LOCAL_SCAN_NETWORKS):
			self.scan_status.setText(
				"Target must be loopback or inside a private RFC1918 IPv4 range."
			)
			return None
		if network.num_addresses > 256:
			self.scan_status.setText("Target range is too large; use at most a /24.")
			return None
		if not self.scan_authorization.isChecked():
			self.scan_status.setText("Confirm authorization for this target before preparing commands.")
			return None
		return str(network) if network.prefixlen < 32 else str(network.network_address)

	def prepare_defensive_check(self, check_type):
		target = self.validated_scan_target()
		if target is None:
			return

		if check_type == "ports":
			commands = (
				"use auxiliary/scanner/portscan/tcp\n"
				f"set RHOSTS {target}\n"
				"set PORTS 22,80,443,445,3389\n"
				"set THREADS 10\n"
				"show options\n"
				"run"
			)
			label = "TCP service inventory"
		elif check_type == "http":
			commands = (
				"use auxiliary/scanner/http/title\n"
				f"set RHOSTS {target}\n"
				"set RPORT 80\n"
				"show options\n"
				"run"
			)
			label = "HTTP title inventory"
		else:
			self.scan_status.setText("Unknown check selection.")
			return

		self.scan_command_output.setPlainText(commands)
		self.scan_status.setText(
			f"{label} prepared for {target}. Review options before running in msfconsole."
		)

	def copy_scan_commands(self):
		commands = self.scan_command_output.toPlainText().strip()
		if not commands:
			self.scan_status.setText("There are no prepared commands to copy.")
			return
		QApplication.clipboard().setText(commands)
		self.scan_status.setText("Copied. Review the commands before pasting into msfconsole.")

	def _build_report_tab(self):
		page = QWidget()
		layout = QVBoxLayout(page)
		layout.setContentsMargins(24, 22, 24, 22)
		layout.setSpacing(12)

		heading = QLabel("Assessment report")
		heading.setStyleSheet("font-size: 15pt; font-weight: 700; color: #f2f5f2;")
		intro = QLabel(
			"Keep scope and evidence together. This workspace is local-only and does not test assets."
		)
		intro.setObjectName("hint")
		intro.setWordWrap(True)
		layout.addWidget(heading)
		layout.addWidget(intro)

		engagement_form = QFormLayout()
		engagement_form.setHorizontalSpacing(18)
		engagement_form.setVerticalSpacing(10)
		self.engagement_input = QLineEdit()
		self.engagement_input.setPlaceholderText("Community assessment name")
		self.scope_input = QPlainTextEdit()
		self.scope_input.setPlaceholderText(
			"Document the authorized assets, owner, and assessment window."
		)
		self.scope_input.setMaximumHeight(74)
		engagement_form.addRow("ENGAGEMENT", self.engagement_input)
		engagement_form.addRow("AUTHORIZED SCOPE", self.scope_input)
		layout.addLayout(engagement_form)

		finding_form = QFormLayout()
		finding_form.setHorizontalSpacing(18)
		finding_form.setVerticalSpacing(10)
		self.finding_title_input = QLineEdit()
		self.finding_title_input.setPlaceholderText("Short, evidence-based finding")
		self.finding_asset_input = QLineEdit()
		self.finding_asset_input.setPlaceholderText("Asset identifier or hostname")
		self.finding_severity = QComboBox()
		self.finding_severity.addItems(
			["Informational", "Low", "Medium", "High", "Critical"]
		)
		self.finding_evidence_input = QPlainTextEdit()
		self.finding_evidence_input.setPlaceholderText(
			"Paste relevant, sanitized evidence or observed output."
		)
		self.finding_evidence_input.setMaximumHeight(82)
		self.finding_remediation_input = QPlainTextEdit()
		self.finding_remediation_input.setPlaceholderText(
			"Recommended mitigation or follow-up."
		)
		self.finding_remediation_input.setMaximumHeight(72)
		finding_form.addRow("FINDING", self.finding_title_input)
		finding_form.addRow("ASSET", self.finding_asset_input)
		finding_form.addRow("SEVERITY", self.finding_severity)
		finding_form.addRow("EVIDENCE", self.finding_evidence_input)
		finding_form.addRow("REMEDIATION", self.finding_remediation_input)
		layout.addLayout(finding_form)

		actions = QHBoxLayout()
		self.report_status = QLabel("No findings recorded")
		self.report_status.setObjectName("hint")
		actions.addWidget(self.report_status)
		actions.addStretch(1)
		self.add_finding_button = QPushButton("Add Finding")
		self.add_finding_button.setObjectName("primaryButton")
		self.add_finding_button.clicked.connect(self.add_finding)
		self.remove_finding_button = QPushButton("Remove Selected")
		self.remove_finding_button.clicked.connect(self.remove_selected_finding)
		self.export_report_button = QPushButton("Export Markdown")
		self.export_report_button.clicked.connect(self.export_report)
		actions.addWidget(self.add_finding_button)
		actions.addWidget(self.remove_finding_button)
		actions.addWidget(self.export_report_button)
		layout.addLayout(actions)

		self.findings_table = QTableWidget(0, 3)
		self.findings_table.setHorizontalHeaderLabels(["Severity", "Finding", "Asset"])
		self.findings_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
		self.findings_table.setSelectionBehavior(
			QTableWidget.SelectionBehavior.SelectRows
		)
		self.findings_table.setSelectionMode(
			QTableWidget.SelectionMode.SingleSelection
		)
		self.findings_table.setAlternatingRowColors(True)
		self.findings_table.verticalHeader().setVisible(False)
		header = self.findings_table.horizontalHeader()
		header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
		header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
		header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
		layout.addWidget(self.findings_table, 1)
		return page

	def add_finding(self):
		if not self.scope_input.toPlainText().strip():
			self.report_status.setText("Document authorized scope before adding findings.")
			return
		title = self.finding_title_input.text().strip()
		asset = self.finding_asset_input.text().strip()
		if not title or not asset:
			self.report_status.setText("A finding title and asset are required.")
			return

		finding = {
			"title": title,
			"asset": asset,
			"severity": self.finding_severity.currentText(),
			"evidence": self.finding_evidence_input.toPlainText().strip(),
			"remediation": self.finding_remediation_input.toPlainText().strip(),
		}
		self.findings.append(finding)
		row = self.findings_table.rowCount()
		self.findings_table.insertRow(row)
		for column, key in enumerate(("severity", "title", "asset")):
			self.findings_table.setItem(
				row, column, QTableWidgetItem(finding[key])
			)
		self.finding_title_input.clear()
		self.finding_asset_input.clear()
		self.finding_evidence_input.clear()
		self.finding_remediation_input.clear()
		self.report_status.setText(f"{len(self.findings)} finding(s) recorded")

	def remove_selected_finding(self):
		row = self.findings_table.currentRow()
		if row < 0:
			self.report_status.setText("Select a finding to remove.")
			return
		self.findings_table.removeRow(row)
		self.findings.pop(row)
		self.report_status.setText(f"{len(self.findings)} finding(s) recorded")

	def render_report_markdown(self):
		engagement = self.engagement_input.text().strip() or "Untitled assessment"
		scope = self.scope_input.toPlainText().strip() or "Not provided"
		lines = [
			f"# Security Assessment: {engagement}",
			"",
			"## Authorized Scope",
			"",
			scope,
			"",
			"## Findings",
		]
		if not self.findings:
			lines.extend(["", "No findings recorded."])
		for finding in self.findings:
			lines.extend(
				[
					"",
					f"### {finding['title']}",
					"",
					f"- Severity: {finding['severity']}",
					f"- Asset: {finding['asset']}",
					"",
					"#### Evidence",
					"",
					finding["evidence"] or "No evidence recorded.",
					"",
					"#### Remediation",
					"",
					finding["remediation"] or "No remediation recorded.",
				]
			)
		return "\n".join(lines).rstrip() + "\n"

	def export_report(self):
		file_path, _ = QFileDialog.getSaveFileName(
			self,
			"Export assessment report",
			"assessment-report.md",
			"Markdown files (*.md)",
		)
		if not file_path:
			return
		try:
			with open(file_path, "w", encoding="utf-8") as report_file:
				report_file.write(self.render_report_markdown())
		except OSError as exc:
			self.report_status.setText(f"Could not export report: {exc}")
		else:
			self.report_status.setText(f"Report exported: {file_path}")

	def _append_command(self, command):
		if self.command_output.toPlainText():
			self.command_output.appendPlainText("")
		self.command_output.appendPlainText(command)
		self.command_status.setText("Command prepared. Copy it into your local msfconsole.")

	def build_search_command(self):
		search_term = self.search_input.text().strip()
		if search_term and not re.fullmatch(r"[A-Za-z0-9_.-]+", search_term):
			self.command_status.setText("Use one search term containing letters, numbers, . _ or -.")
			return
		module_type = MODULE_TYPES[self.module_type.currentText()]
		command = f"search type:{module_type}"
		if search_term:
			command += f" {search_term}"
		self._append_command(command)

	def _validated_module_path(self):
		module_path = self.module_path_input.text().strip().strip("/")
		if not re.fullmatch(r"[A-Za-z0-9_./-]+", module_path):
			self.command_status.setText("Enter a valid module path, such as auxiliary/scanner/http/title.")
			return None
		if ".." in module_path.split("/"):
			self.command_status.setText("Module path cannot contain '..' segments.")
			return None
		return module_path

	def build_info_command(self):
		module_path = self._validated_module_path()
		if module_path:
			self._append_command(f"info {module_path}")

	def build_options_command(self):
		module_path = self._validated_module_path()
		if module_path:
			self._append_command(f"use {module_path}\nshow options")

	def copy_command(self):
		command = self.command_output.toPlainText().strip()
		if not command:
			self.command_status.setText("There is no generated command to copy.")
			return
		QApplication.clipboard().setText(command)
		self.command_status.setText("Copied. Paste the command into your local msfconsole.")

	def clear_console_output(self):
		self.console_output.clear()
		self.command_output.clear()
		self.command_status.setText("Output cleared")


def main():
	app = QApplication(sys.argv)
	window = MainWindow()
	window.show()
	sys.exit(app.exec())


if __name__ == "__main__":
	main()
