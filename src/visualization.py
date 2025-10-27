import pydantic
import networkx as nx
import matplotlib.pyplot as plt
import numpy as np

import PIL
import pathlib
import os.path

import models
import verbose

BASE_DIR = pathlib.Path(__file__).resolve().parent


class Visualizer(pydantic.BaseModel):
    """Visualizes the data using a network graph."""

    def create_visualization_image(
        self,
        analyzed_ipv4s: list[models.IPV4],
        analyzed_cidrs: list[models.CIDR],
        analyzed_fqdns: list[models.FQDN],
        analyzed_urls: list[models.URL],
        out_path: str = 'network.png',
    ) -> None:
        verbose.debug('Specify an icon per entity.')
        icons_paths = {
            'ipv4': os.path.join(BASE_DIR, 'icons', 'ipv4.png'),
            'cidr': os.path.join(BASE_DIR, 'icons', 'cidr.png'),
            'fqdn': os.path.join(BASE_DIR, 'icons', 'fqdn.png'),
            'url': os.path.join(BASE_DIR, 'icons', 'url.png'),
            '404': os.path.join(BASE_DIR, 'icons', '404.png'),
            'target': os.path.join(BASE_DIR, 'icons', 'target.png'),
        }
        icons = {k: PIL.Image.open(fname) for k, fname in icons_paths.items()}

        verbose.debug('Create the network graph nodes.')
        total = len(analyzed_ipv4s) + len(analyzed_cidrs) + len(analyzed_fqdns) + len(analyzed_urls)
        G = nx.Graph()
        if total > 1:
            G.add_node('center', image=icons['target'], name='center')
        for ip in analyzed_ipv4s:
            G.add_node(ip.ipv4, image=icons['ipv4'], name=ip.ipv4)
            if total > 1:
                G.add_edge('center', ip.ipv4)

        for c in analyzed_cidrs:
            G.add_node(c.cidr, image=icons['cidr'], name=c.cidr)
            if total > 1:
                G.add_edge('center', c.cidr)

        for f in analyzed_fqdns:
            G.add_node(f.fqdn, image=icons['fqdn'], name=f.fqdn)
            if total > 1:
                G.add_edge('center', f.fqdn)

            _chain_wo_fqdn = [node for node in f.dns_chain if node != f.fqdn]
            if _chain_wo_fqdn:
                for link in _chain_wo_fqdn:
                    G.add_node(link, image=icons['fqdn'], name=link)
                    G.add_edge(f.fqdn, link)

            if f.hosts_found:
                for ip in f.destination_ips:
                    _ipnode = f'{f.fqdn}_{ip}'
                    G.add_node(_ipnode, image=icons['ipv4'], name=ip.ipv4)
                    G.add_edge(f.dns_chain[-1], _ipnode)
            else:
                error = f'{f.fqdn} not found'
                G.add_node(error, image=icons['404'], name='404', kind='404')
                G.add_edge(f.dns_chain[-1], error)

        for u in analyzed_urls:
            G.add_node(u.url, image=icons['url'], name=u.url)
            if total > 1:
                G.add_edge('center', u.url)

            G.add_node(u.fqdn.fqdn, image=icons['fqdn'], name=u.fqdn.fqdn)
            G.add_edge(u.url, u.fqdn.fqdn)

            _chain_wo_fqdn = [node for node in u.fqdn.dns_chain if node != u.fqdn.fqdn]
            if _chain_wo_fqdn:
                for link in _chain_wo_fqdn:
                    G.add_node(link, image=icons['fqdn'], name=link)
                    G.add_edge(u.fqdn.fqdn, link)

            if u.fqdn.hosts_found:
                for ip in u.fqdn.destination_ips:
                    _ipnode = f'{u.fqdn.fqdn}_{ip}'
                    G.add_node(_ipnode, image=icons['ipv4'], name=ip.ipv4)
                    G.add_edge(u.fqdn.dns_chain[-1], _ipnode)
            else:
                error = f'{u.fqdn.fqdn} not found'
                G.add_node(error, image=icons['404'], name='404', kind='404')
                G.add_edge(u.fqdn.dns_chain[-1], error)

        verbose.debug('Initialize the figure.')
        pos = nx.kamada_kawai_layout(G)
        if total > 1:
            pos['center'] = np.array([0.0, 0.0])
        fig, ax = plt.subplots(figsize=(19.2, 10.8))

        verbose.debug('Draw the edges.')
        nx.draw_networkx_edges(
            G,
            pos=pos,
            ax=ax,
            arrows=True,
            min_source_margin=15,
            min_target_margin=15,
        )

        # --- Draw ---
        verbose.debug('Draw the icons.')
        tr_figure = ax.transData.transform
        tr_axes = fig.transFigure.inverted().transform
        icon_size = (ax.get_xlim()[1] - ax.get_xlim()[0]) * 0.01
        icon_center = icon_size / 2.0
        for n in G.nodes:
            xf, yf = tr_figure(pos[n])
            xa, ya = tr_axes((xf, yf))
            # get overlapped axes and plot icon
            a = plt.axes([xa - icon_center, ya - icon_center, icon_size, icon_size])
            a.imshow(G.nodes[n]['image'])
            a.axis('off')

        verbose.debug('Add the labels.')
        label_options = {'ec': 'k', 'fc': 'white', 'alpha': 0.7}
        for n in G.nodes:
            node_name = G.nodes[n].get('name', '')

            if node_name == 'center':
                continue

            ax.text(
                pos[n][0],
                pos[n][1] + 0.035,  # offset upward
                node_name,
                fontsize=6,
                bbox=label_options,
                ha='center',  # <-- center horizontally
                va='bottom',  # <-- place box just above the node
            )

        verbose.debug('Save the image.')
        ax.set_axis_off()  # hides axes and ticks
        plt.savefig(out_path, dpi=100, bbox_inches='tight')
