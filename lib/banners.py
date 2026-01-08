# Copyright 2023-2024 David Kneipp <david@davidkneipp.com>
# Copyright 2024-2025 Lennart Rosam <hello@takuto.de>
# Copyright 2024-2025 Alexander Couzens <lynxis@fe80.eu>
# SPDX-License-Identifier: AGPL-3.0-or-later
class Banners:

    def diameterService(self) -> str:
        bannerText = """
                                                     
 ######            ##   ##   #####    #####  
 ##   ##           ##   ##  ##   ##  ##   ## 
 ##   ##  ##  ##   ##   ##  ##       ##      
 ######   ##  ##   #######   #####    #####  
 ##       ##  ##   ##   ##       ##       ## 
 ##       ##  ##   ##   ##  ##   ##  ##   ## 
 ##        #####   ##   ##   #####    #####  
              ##                             
           ####                              

              Diameter Service

"""
        return bannerText


    def hssService(self) -> str:
        bannerText = """
                                                     
 ######            ##   ##   #####    #####  
 ##   ##           ##   ##  ##   ##  ##   ## 
 ##   ##  ##  ##   ##   ##  ##       ##      
 ######   ##  ##   #######   #####    #####  
 ##       ##  ##   ##   ##       ##       ## 
 ##       ##  ##   ##   ##  ##   ##  ##   ## 
 ##        #####   ##   ##   #####    #####  
              ##                             
           ####                              

                 HSS Service

"""
        return bannerText

    def georedService(self) -> str:
        bannerText = """
                                                     
 ######            ##   ##   #####    #####  
 ##   ##           ##   ##  ##   ##  ##   ## 
 ##   ##  ##  ##   ##   ##  ##       ##      
 ######   ##  ##   #######   #####    #####  
 ##       ##  ##   ##   ##       ##       ## 
 ##       ##  ##   ##   ##  ##   ##  ##   ## 
 ##        #####   ##   ##   #####    #####  
              ##                             
           ####                              

        Geographic Redundancy Service

"""
        return bannerText

    def metricService(self) -> str:
        bannerText = """
                                                     
 ######            ##   ##   #####    #####  
 ##   ##           ##   ##  ##   ##  ##   ## 
 ##   ##  ##  ##   ##   ##  ##       ##      
 ######   ##  ##   #######   #####    #####  
 ##       ##  ##   ##   ##       ##       ## 
 ##       ##  ##   ##   ##  ##   ##  ##   ## 
 ##        #####   ##   ##   #####    #####  
              ##                             
           ####                              

               Metric Service

"""
        return bannerText

    def logService(self) -> str:
        bannerText = """
                                                     
 ######            ##   ##   #####    #####  
 ##   ##           ##   ##  ##   ##  ##   ## 
 ##   ##  ##  ##   ##   ##  ##       ##      
 ######   ##  ##   #######   #####    #####  
 ##       ##  ##   ##   ##       ##       ## 
 ##       ##  ##   ##   ##  ##   ##  ##   ## 
 ##        #####   ##   ##   #####    #####  
              ##                             
           ####                              

                 Log Service

"""
        return bannerText

    def databaseService(self) -> str:
        bannerText = """
                                                     
 ######            ##   ##   #####    #####  
 ##   ##           ##   ##  ##   ##  ##   ## 
 ##   ##  ##  ##   ##   ##  ##       ##      
 ######   ##  ##   #######   #####    #####  
 ##       ##  ##   ##   ##       ##       ## 
 ##       ##  ##   ##   ##  ##   ##  ##   ## 
 ##        #####   ##   ##   #####    #####  
              ##                             
           ####                              

                Database Service

"""
        return bannerText

    def gsupService(self) -> str:
        bannerText = """

         ######            ##   ##   #####    #####  
         ##   ##           ##   ##  ##   ##  ##   ## 
         ##   ##  ##  ##   ##   ##  ##       ##      
         ######   ##  ##   #######   #####    #####  
         ##       ##  ##   ##   ##       ##       ## 
         ##       ##  ##   ##   ##  ##   ##  ##   ## 
         ##        #####   ##   ##   #####    #####  
                      ##                             
                   ####                              

                        GSUP Service

        """
        return bannerText
