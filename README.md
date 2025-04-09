# Wallet Scanner (Go)

Генератор и сканер MetaMask-кошельков (EVM) на Go.

## Установка
go mod tidy

## Запуск
go run main.go --find 10 --range 0-10

## Прокси
Файл proxies.txt с SOCKS5, HTTP, HTTPS. Один прокси на строку.

## Результат
Результаты сохраняются в found.csv.
