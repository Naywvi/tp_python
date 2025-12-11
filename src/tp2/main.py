""" Shellcode Analyzer - Analyse et desassemble du shellcode x86 32 bits. - Nagib Lakhdari """

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.units import cm
import logging, argparse, sys, os

class ShellcodeAnalyzer:
    """ Classe principale pour analyser les shellcodes. """
    
    def __init__(self, shellcode_bytes) -> None:
        """ Initialise l'analyseur de shellcode avec les octets donnés. """

        self.shellcode = shellcode_bytes
        self.strings = []
        self.instructions = []
    
    def get_shellcode_strings(self, min_len=4) -> list[str]:
        """ Extrait les chaines ASCII du shellcode. """

        self.strings = []
        current = ""
        
        for byte in self.shellcode:
            if 0x20 <= byte <= 0x7e: current += chr(byte)
            else:
                if len(current) >= min_len: self.strings.append(current)
                current = ""
        
        if len(current) >= min_len: self.strings.append(current)
        return self.strings
    
    def get_capstone_analysis(self) -> list[str]:
        """ Desassemble le shellcode avec Capstone. """

        self.instructions = []
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        
        for insn in md.disasm(self.shellcode, 0x0):
            line = f"0x{insn.address:04x}: {insn.mnemonic} {insn.op_str}"
            self.instructions.append(line)
        return self.instructions
    
    def get_llm_analysis(self) -> str:
        """ Analyse le shellcode et genere un rapport. """

        analysis = []
        analysis.append(f"Taille: {len(self.shellcode)} octets")
        
        if self.strings: analysis.append(f"Chaines trouvees: {', '.join(self.strings)}")
        
        suspicious = []
        strings_lower = ' '.join(self.strings).lower()
        
        if 'cmd' in strings_lower or 'exe' in strings_lower: suspicious.append("execution de commande")
        if 'url' in strings_lower or 'http' in strings_lower: suspicious.append("telechargement")
        if '.dll' in strings_lower: suspicious.append("chargement DLL")
        if 'admin' in strings_lower or 'add' in strings_lower: suspicious.append("modification utilisateur")
        if 'net ' in strings_lower or 'localg' in strings_lower: suspicious.append("commandes reseau")
        if 'ws2_32' in strings_lower or 'ws2_' in strings_lower: suspicious.append("connexion socket")
        
        asm_text = ' '.join(self.instructions).lower()
        
        if 'push 0x40' in asm_text: suspicious.append("allocation memoire executable")
        if 'call' in asm_text and 'push' in asm_text: suspicious.append("appels API Windows")
        
        if suspicious: analysis.append(f"Comportements suspects: {', '.join(suspicious)}")
        
        shellcode_type = "inconnu"
        if "connexion socket" in suspicious: shellcode_type = "reverse shell / stager"
        elif "telechargement" in suspicious: shellcode_type = "downloader"
        elif "execution de commande" in suspicious: shellcode_type = "command execution"
        elif "modification utilisateur" in suspicious: shellcode_type = "privilege escalation / user add"
        elif "chargement DLL" in suspicious: shellcode_type = "DLL loader"
        
        analysis.append(f"Type probable: {shellcode_type}")
        return "\n".join(analysis)
    
    def generate_pdf_report(self, output_path, name="shellcode") -> str:
        """ Genere un rapport PDF de l'analyse. """
        
        doc = SimpleDocTemplate(output_path, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []
        
        title_style = ParagraphStyle('CustomTitle', parent=styles['Title'], fontSize=20, spaceAfter=20)
        code_style = ParagraphStyle('Code', parent=styles['Normal'], fontName='Courier', fontSize=7, leading=9)
        
        story.append(Paragraph(f"Rapport d'analyse - {name}", title_style))
        story.append(Spacer(1, 10))
        
        story.append(Paragraph("Informations generales", styles['Heading2']))
        info_data = [
            ["Taille", f"{len(self.shellcode)} octets"],
            ["Instructions", f"{len(self.instructions)}"],
            ["Chaines", f"{len(self.strings)}"]
        ]
        info_table = Table(info_data, colWidths=[5*cm, 10*cm])
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ]))
        story.append(info_table)
        story.append(Spacer(1, 15))
        
        if self.strings:
            story.append(Paragraph("Chaines extraites", styles['Heading2']))
            for s in self.strings:
                story.append(Paragraph(f"- {s}", styles['Normal']))
            story.append(Spacer(1, 15))
        
        story.append(Paragraph("Analyse comportementale", styles['Heading2']))
        for line in self.get_llm_analysis().split('\n'):
            story.append(Paragraph(line, styles['Normal']))
        story.append(Spacer(1, 15))
        
        story.append(Paragraph("Desassemblage", styles['Heading2']))
        asm_text = "<br/>".join(self.instructions)
        story.append(Paragraph(asm_text, code_style))
        
        doc.build(story)
        return output_path


def parse_shellcode(data) -> bytes:
    """ Parse le shellcode depuis une representation en string. """

    data = data.strip()
    
    if '\\x' in data:
        hex_str = data.replace('\\x', '').replace(' ', '').replace('\n', '')
        return bytes.fromhex(hex_str)
    
    if all(c in '0123456789abcdefABCDEF \n' for c in data):  return bytes.fromhex(data.replace(' ', '').replace('\n', ''))
    
    return data.encode()


def analyze_file(filepath, output_pdf) -> None:
    """ Analyse un fichier shellcode et genere le rapport. """

    with open(filepath, 'r') as f:
        raw = f.read()
    
    shellcode = parse_shellcode(raw)
    name = os.path.basename(filepath).replace('.txt', '')
    
    logger.info(f"Analyse de {name} ({len(shellcode)} octets)")
    
    analyzer = ShellcodeAnalyzer(shellcode)
    
    logger.info("Extraction des chaines")
    strings = analyzer.get_shellcode_strings()
    if strings:
        for s in strings: logger.info(f"  {s}")
    else: logger.info("  Aucune chaine")
    
    logger.info("Desassemblage Capstone")
    instructions = analyzer.get_capstone_analysis()
    for insn in instructions: logger.info(f"  {insn}")
    
    logger.info("Analyse")
    for line in analyzer.get_llm_analysis().split('\n'): logger.info(f"  {line}")
    
    analyzer.generate_pdf_report(output_pdf, name)
    logger.info(f"Rapport genere: {output_pdf}")


def main() -> None:
    """ Point d'entrée principal du script. """
    
    parser = argparse.ArgumentParser(description="Shellcode Analyzer")
    parser.add_argument("-f", "--file", help="Fichier contenant le shellcode")
    parser.add_argument("-s", "--shellcode", help="Shellcode en hex")
    parser.add_argument("-o", "--output", help="Fichier PDF de sortie", default="rapport.pdf")
    parser.add_argument("--all", action="store_true", help="Analyser tous les shellcodes")
    
    args = parser.parse_args()
    
    if args.all:
        files = [
            ("shellcode_easy.txt", "rapport_easy.pdf"),
            ("shellcode_medium.txt", "rapport_medium.pdf"),
            ("shellcode_hard.txt", "rapport_hard.pdf"),
        ]
        for shellcode_file, pdf_file in files:
            if os.path.exists(shellcode_file):
                analyze_file(shellcode_file, pdf_file)
            else: logger.warning(f"Fichier non trouve: {shellcode_file}")
        return
    
    if args.file: analyze_file(args.file, args.output)
    elif args.shellcode:
        shellcode = parse_shellcode(args.shellcode)
        analyzer = ShellcodeAnalyzer(shellcode)
        analyzer.get_shellcode_strings()
        analyzer.get_capstone_analysis()
        
        logger.info(f"Shellcode charge: {len(shellcode)} octets")
        for s in analyzer.strings: logger.info(f"  String: {s}")
        for insn in analyzer.instructions: logger.info(f"  {insn}")
        for line in analyzer.get_llm_analysis().split('\n'): logger.info(f"  {line}")
        
        analyzer.generate_pdf_report(args.output)
        logger.info(f"Rapport: {args.output}")
    else:
        logger.error("Utiliser -f <fichier>, -s <shellcode> ou --all")
        sys.exit(1)


if __name__ == "__main__":
    main()