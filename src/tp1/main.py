""" IDS Network Analyzer - TP 1 - Nagib Lakhdari """

from collections import defaultdict
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, Raw, Ether, conf
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
from reportlab.lib.units import cm
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import sys, logging, re

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)


class NetworkAnalyzer:
    
    SQL_PATTERNS = [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
        r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
        r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
        r"union.*select",
        r"select.*from",
        r"insert.*into",
        r"drop.*table",
        r"delete.*from",
        r"update.*set",
    ]
    
    XSS_PATTERNS = [
        r"<script[^>]*>",
        r"javascript:",
        r"on\w+\s*=",
        r"<iframe",
        r"<object",
        r"<embed",
    ]
    
    def __init__(self, interface=None, packet_count=100) -> None:
        """Initialise l'analyseur reseau."""

        self.interface = interface or conf.iface
        self.packet_count = packet_count
        self.packets = []
        self.protocol_stats = defaultdict(int)
        self.attacks = []
        self.legitimate_traffic = []
        
    def get_protocol_name(self, pkt) -> str:
        """ Retourne le nom du protocole principal du paquet. """
        
        if ARP in pkt:return "ARP"
        if DNS in pkt:return "DNS"
        if ICMP in pkt:return "ICMP"   
        if TCP in pkt:
            dport = pkt[TCP].dport
            sport = pkt[TCP].sport
            if 80 in (dport, sport):return "HTTP"
            if 443 in (dport, sport):return "HTTPS"
            if 22 in (dport, sport):return "SSH"
            if 21 in (dport, sport):return "FTP"
                
            return "TCP"
        if UDP in pkt:return "UDP"
        if IP in pkt:return "IP"
        return "OTHER"
    
    def detect_sql_injection(self, payload) -> bool:
        """ Detecte les tentatives d'injection SQL dans le payload. """
        
        for pattern in self.SQL_PATTERNS:
            if re.search(pattern, payload, re.IGNORECASE):return True
        return False
    
    def detect_xss(self, payload) -> bool:
        """ Detecte les tentatives d'attaque XSS dans le payload. """

        for pattern in self.XSS_PATTERNS:
            if re.search(pattern, payload, re.IGNORECASE):return True
        return False
    
    def analyze_packet(self, pkt) -> None:
        """ Analyse un paquet pour detecter les attaques. """
        self.packets.append(pkt)
        proto = self.get_protocol_name(pkt)
        self.protocol_stats[proto] += 1
        
        src_ip = pkt[IP].src if IP in pkt else "N/A"
        dst_ip = pkt[IP].dst if IP in pkt else "N/A"
        src_mac = pkt[Ether].src if Ether in pkt else "N/A"
        
        if Raw in pkt:
            try:
                payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                
                if self.detect_sql_injection(payload):
                    attack_info = {
                        "type": "SQL Injection",
                        "protocol": proto,
                        "src_ip": src_ip,
                        "src_mac": src_mac,
                        "details": "Tentative injection SQL detectee",
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                    self.attacks.append(attack_info)
                    logger.warning(f"SQL Injection detectee depuis {src_ip}")
                    return
                
                if self.detect_xss(payload):
                    attack_info = {
                        "type": "XSS Attack",
                        "protocol": proto,
                        "src_ip": src_ip,
                        "src_mac": src_mac,
                        "details": "Tentative XSS detectee",
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                    self.attacks.append(attack_info)
                    logger.warning(f"XSS detecte depuis {src_ip}")
                    return
            except:
                pass
        
        traffic_info = {
            "protocol": proto,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "status": "Legitime"
        }
        self.legitimate_traffic.append(traffic_info)
    
    def capture(self) -> None:
        """ Capture les paquets reseau sur l'interface specifiee. """

        logger.info(f"Capture sur {self.interface} ({self.packet_count} paquets)")
        try:
            sniff(
                iface=self.interface,
                prn=self.analyze_packet,
                count=self.packet_count,
                store=False
            )
        except PermissionError:
            logger.error("Privileges admin requis")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Erreur capture: {e}")
            sys.exit(1)
    
    def generate_chart(self, output_path) -> str | None:
        """ Genere un graphique des statistiques des protocoles. """

        if not self.protocol_stats:return None
        
        protocols = list(self.protocol_stats.keys())
        counts = list(self.protocol_stats.values())
        
        _, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
        colors_list = plt.cm.Set3(range(len(protocols)))
        
        ax1.bar(protocols, counts, color=colors_list)
        ax1.set_xlabel('Protocole')
        ax1.set_ylabel('Nombre de paquets')
        ax1.set_title('Distribution des protocoles')
        ax1.tick_params(axis='x', rotation=45)
        
        ax2.pie(counts, labels=protocols, autopct='%1.1f%%', colors=colors_list)
        ax2.set_title('Repartition des protocoles')
        
        plt.tight_layout()
        plt.savefig(output_path, dpi=150, bbox_inches='tight')
        plt.close()
        
        return output_path
    
    def generate_report(self, output_path="rapport_tp_1_ids.pdf") -> str:
        """ Genere un rapport PDF de l'analyse reseau. """

        doc = SimpleDocTemplate(output_path, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []
        
        title_style = ParagraphStyle('CustomTitle', parent=styles['Title'], fontSize=24, spaceAfter=30)
        
        story.append(Paragraph("Rapport d'Analyse Reseau IDS", title_style))
        story.append(Paragraph(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        story.append(Paragraph(f"Interface: {self.interface}", styles['Normal']))
        story.append(Paragraph(f"Paquets captures: {len(self.packets)}", styles['Normal']))
        story.append(Spacer(1, 20))
        
        story.append(Paragraph("Statistiques des Protocoles", styles['Heading1']))
        story.append(Spacer(1, 10))
        
        # Import temporaire pour enregistrer le graphique
        import tempfile, os
        chart_path = os.path.join(tempfile.gettempdir(), "chart_ids.png")
        if self.generate_chart(chart_path):
            story.append(Image(chart_path, width=16*cm, height=7*cm))
            story.append(Spacer(1, 20))
        
        table_data = [["Protocole", "Nombre de paquets", "Pourcentage"]]
        total = sum(self.protocol_stats.values())
        for proto, count in sorted(self.protocol_stats.items(), key=lambda x: x[1], reverse=True):
            pct = (count / total * 100) if total > 0 else 0
            table_data.append([proto, str(count), f"{pct:.1f}%"])
        
        table = Table(table_data, colWidths=[6*cm, 5*cm, 4*cm])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        story.append(table)
        story.append(PageBreak())
        
        story.append(Paragraph("Analyse de Securite", styles['Heading1']))
        story.append(Spacer(1, 10))
        
        if self.attacks:
            story.append(Paragraph(f"Alertes: {len(self.attacks)} menaces detectees", styles['Heading2']))
            story.append(Spacer(1, 10))
            
            attack_data = [["Type", "Protocole", "IP Source", "MAC Source", "Timestamp"]]
            for attack in self.attacks:
                attack_data.append([
                    attack["type"],
                    attack["protocol"],
                    attack["src_ip"],
                    attack["src_mac"],
                    attack["timestamp"]
                ])
            
            attack_table = Table(attack_data, colWidths=[3.5*cm, 2.5*cm, 3*cm, 4*cm, 3.5*cm])
            attack_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.red),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightcoral),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            story.append(attack_table)
            story.append(Spacer(1, 20))
            
            story.append(Paragraph("Details des attaques:", styles['Heading3']))
            for i, attack in enumerate(self.attacks, 1):
                story.append(Paragraph(f"{i}. {attack['type']}", styles['Normal']))
                story.append(Paragraph(f"   Attaquant: {attack['src_ip']} ({attack['src_mac']})", styles['Normal']))
                story.append(Spacer(1, 5))
        else:
            story.append(Paragraph("Aucune menace detectee", styles['Heading2']))
            story.append(Paragraph("Le trafic analyse semble légitime.", styles['Normal']))
            story.append(Spacer(1, 10))
            
            status_table = Table([
                ["Statut", "OK"],
                ["Menaces", "0"],
                ["Trafic legitime", str(len(self.legitimate_traffic))]
            ], colWidths=[6*cm, 6*cm])
            status_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.lightgreen),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ]))
            story.append(status_table)
        
        doc.build(story)
        logger.info(f"Rapport généré: {output_path}")
        return output_path


def main() -> None:
    """ Point d'entree principal. """
    
    import argparse
    
    parser = argparse.ArgumentParser(description="IDS Network Analyzer")
    parser.add_argument("-i", "--interface", help="Interface reseau", default=None)
    parser.add_argument("-c", "--count", type=int, help="Nombre de paquets", default=100)
    parser.add_argument("-o", "--output", help="Fichier PDF", default="rapport_ids_tp_1.pdf")
    
    args = parser.parse_args()
    
    analyzer = NetworkAnalyzer(interface=args.interface, packet_count=args.count)
    
    logger.info("TP 1 - Systeme de Detection d'Intrusion")
    analyzer.capture()
    
    logger.info(f"Protocoles: {list(analyzer.protocol_stats.keys())}")
    logger.info(f"Total: {sum(analyzer.protocol_stats.values())} paquets")
    
    if analyzer.attacks:
        logger.warning(f"{len(analyzer.attacks)} attaque(s) detectee(s)")
    else:
        logger.info("Aucune menace - trafic TOUT PROPRE")
    
    analyzer.generate_report(args.output)


if __name__ == "__main__":
    main()
