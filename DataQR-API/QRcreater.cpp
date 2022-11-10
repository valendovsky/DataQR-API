#include "QRcreater.h"

#include<iostream>
#include <string>
#include <cstdlib>
#include <cstdio>
#include <cerrno>
#include<numeric>
#include <fstream>
#include <sstream>
#include <thread>

#include <qrencode.h>
#include <png.h>

#include "Constants.h"
#include "IWriteLog.h"
#include "ScreenLog.h"


// Метод логирования
void QRcreater::printInfo(const std::string& message, IWriteLog& typeLog)
{
    typeLog.writeLog("INFO QRcreater: " + message);
}

// Помещает QR-код в png файл
int QRcreater::createPNGfile(QRcode* qrCode, const char* pngFile)
{
    FILE* fp;
    png_structp png_ptr;
    png_infop info_ptr;
    png_colorp palette;
    png_byte alpha_values[2];
    unsigned char* row, * p, * q;
    int x, y, xx, yy, bit;
    int realwidth;
    ScreenLog toScreen;
    const double INCHES_PER_METER = 100.0 / 2.54;

    realwidth = (qrCode->width + m_margin * 2) * m_size;
    row = (unsigned char*)malloc((realwidth + 7) / 8);
    if (row == NULL) {
        printInfo("Failed to allocate memory.", toScreen);

        return EXIT_FAILURE;
    }

    if (pngFile[0] == '-' && pngFile[1] == '\0') {
        fp = stdout;
    }
    else {
        fp = fopen(pngFile, "wb");
        if (fp == NULL) {
            printInfo("Failed to create file: " + std::string(pngFile), toScreen);
            perror(NULL);
            free(row);

            return EXIT_FAILURE;
        }
    }

    png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (png_ptr == NULL) {
        printInfo("Failed to initialize PNG writer.", toScreen);
        fclose(fp);
        free(row);

        return EXIT_FAILURE;
    }

    info_ptr = png_create_info_struct(png_ptr);
    if (info_ptr == NULL) {
        printInfo("Failed to initialize PNG write.", toScreen);
        fclose(fp);
        free(row);

        return EXIT_FAILURE;
    }

    if (setjmp(png_jmpbuf(png_ptr))) {
        png_destroy_write_struct(&png_ptr, &info_ptr);
        printInfo("Failed to write PNG image.", toScreen);
        fclose(fp);
        free(row);

        return EXIT_FAILURE;
    }

    palette = (png_colorp)malloc(sizeof(png_color) * 2);
    if (palette == NULL) {
        printInfo("Failed to allocate memory.", toScreen);
        fclose(fp);
        free(row);

        return EXIT_FAILURE;
    }
    palette[0].red = m_fg_color[0];
    palette[0].green = m_fg_color[1];
    palette[0].blue = m_fg_color[2];
    palette[1].red = m_bg_color[0];
    palette[1].green = m_bg_color[1];
    palette[1].blue = m_bg_color[2];
    alpha_values[0] = m_fg_color[3];
    alpha_values[1] = m_bg_color[3];
    png_set_PLTE(png_ptr, info_ptr, palette, 2);
    png_set_tRNS(png_ptr, info_ptr, alpha_values, 2, NULL);

    png_init_io(png_ptr, fp);
    png_set_IHDR(png_ptr, info_ptr,
        realwidth, realwidth,
        1,
        PNG_COLOR_TYPE_PALETTE,
        PNG_INTERLACE_NONE,
        PNG_COMPRESSION_TYPE_DEFAULT,
        PNG_FILTER_TYPE_DEFAULT);
    png_set_pHYs(png_ptr, info_ptr,
        m_dpi * INCHES_PER_METER,
        m_dpi * INCHES_PER_METER,
        PNG_RESOLUTION_METER);
    png_write_info(png_ptr, info_ptr);

    memset(row, 0xff, (realwidth + 7) / 8);
    for (y = 0; y < m_margin * m_size; y++) {
        png_write_row(png_ptr, row);
    }

    p = qrCode->data;
    for (y = 0; y < qrCode->width; y++) {
        bit = 7;
        memset(row, 0xff, (realwidth + 7) / 8);
        q = row;
        q += m_margin * m_size / 8;
        bit = 7 - (m_margin * m_size % 8);
        for (x = 0; x < qrCode->width; x++) {
            for (xx = 0; xx < m_size; xx++) {
                *q ^= (*p & 1) << bit;
                bit--;
                if (bit < 0) {
                    q++;
                    bit = 7;
                }
            }
            p++;
        }
        for (yy = 0; yy < m_size; yy++) {
            png_write_row(png_ptr, row);
        }
    }

    memset(row, 0xff, (realwidth + 7) / 8);
    for (y = 0; y < m_margin * m_size; y++) {
        png_write_row(png_ptr, row);
    }

    png_write_end(png_ptr, info_ptr);
    png_destroy_write_struct(&png_ptr, &info_ptr);

    fclose(fp);
    free(row);
    free(palette);
    printInfo("Succesful creation of a PNG file.", toScreen);

    return 0;
}

// Создаёт QR-код и возвращет файл с ним, помещённый в строку
std::string QRcreater::createQRcodePNG(const std::string& qrCodeStr, const std::string& prefixPngFile)
{
    ScreenLog toScreen;
    QRcode* myqrcode;
    myqrcode = QRcode_encodeString(qrCodeStr.c_str(), 4, QR_ECLEVEL_H, QR_MODE_8, 1);
    
    std::ostringstream ssId;
    ssId << std::this_thread::get_id();
    std::string threadFile = prefixPngFile + ssId.str() + ".png";
    int resultPNG = createPNGfile(myqrcode, threadFile.c_str());
    
    QRcode_free(myqrcode);

    if (resultPNG)
    {
        printInfo("Failed creation of a PNG file.", toScreen);

        return ServerConstants::NONE;
    }

    std::ifstream file(threadFile, std::ios::binary);
    if (file.is_open())
    {
        std::ostringstream oss;
        oss << file.rdbuf();
        file.close();
        printInfo("Successful reading of a PNG file.", toScreen);

        // Удаляем ранее созданный файл
        if (!remove(threadFile.c_str()))
        {
            printInfo("The PNG file is successfully deleted.", toScreen);
        }
        else
        {
            printInfo("The file was not deleted.", toScreen);
        }

        return oss.str();
    }
    else
    {
        printInfo("Failed reading of a PNG file.", toScreen);

        return ServerConstants::NONE;
    }
}
