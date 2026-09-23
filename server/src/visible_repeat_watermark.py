import pymupdf

pdf = pymupdf.open("idatest.pdf")

for page in pdf:
    width = page.rect.width
    height = page.rect.height

    positions = [
        (width * 0.15, height * 0.15),
        (width * 0.50, height * 0.35),
        (width * 0.15, height * 0.60),
        (width * 0.40, height * 0.80),]

    for position in positions:
        page.insert_text(
            position, "MY WATERMARK", 
            fontsize=30, 
            color=(0.5, 0.5, 0.5), 
            fill_opacity=0.3)

pdf.save("idatest_watermarked.pdf")
pdf.close()