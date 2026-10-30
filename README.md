# 🛡️ Veille Cyber

Dashboard statique (une seule page HTML) qui agrège :

- **CVE** depuis l'API NVD, avec marquage **CISA KEV** (exploitées activement) et score **EPSS** (probabilité d'exploitation)
- **Actu cyber** depuis les flux RSS de `config.json`
- **Historique** conservé dans `data/` : vues Aujourd'hui / 7 j / 30 j / Tout, histogramme cliquable par jour
- **Watchlist** (`config.json`) : badge ⭐ sur les CVE qui touchent vos produits
- **Alertes** optionnelles (ntfy / Discord) : nouvelle CVE watchlist avec CVSS ≥ `min_cvss`, ou nouvelle entrée KEV

## Mise en route (5 min, gratuit, sans serveur)

1. Créez un dépôt GitHub (public pour GitHub Pages gratuit) et poussez ce dossier.
2. *Settings → Pages* : source = branche `main`, dossier `/docs`.
3. *Actions → veille-cyber → Run workflow* pour la première collecte (backfill de `hot_days` jours).
   Ensuite, elle tourne toutes les 3 h toute seule.
4. Votre dashboard : `https://<user>.github.io/<repo>/`

Secrets optionnels (*Settings → Secrets → Actions*) :
`NVD_API_KEY` (clé gratuite, collecte bien plus rapide), `NTFY_TOPIC` (alertes sur téléphone via l'app ntfy), `DISCORD_WEBHOOK`.

## En local

```bash
pip install -r requirements.txt
python veille.py          # collecte + génère docs/index.html
python veille.py --demo   # rendu avec données fictives, sans réseau
python veille.py --render # regénère la page depuis data/
```

## Réglages (`config.json`)

| Clé | Rôle |
|---|---|
| `hot_days` | fenêtre du premier backfill, et période pour laquelle l'EPSS est rafraîchi |
| `watchlist` | mots-clés cherchés dans la description et les produits CPE |
| `alerts.min_cvss` / `notify_kev` / `max_per_run` | seuils des notifications |
| `feeds` | flux RSS (ajoutez les vôtres) |

## Notes

- Les CVE de NVD arrivent avec quelques heures de retard et sans score au début : « N/A » est normal, le score est complété aux passages suivants.
- Si une source tombe, le script continue avec les autres et garde l'historique.
- Le dépôt grossit lentement (quelques Mo / mois). Les articles de plus de 120 jours ne sont plus affichés.
