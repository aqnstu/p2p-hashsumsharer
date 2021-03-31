# p2p-hashsumsharer
Лабораторная работа по дисциплине "Разработка web-приложений и распределённых информационных систем"

Идея в том, что нам нужно найти ближайшего соседа, и отправить информацию, что у нас есть файл. Мы формируем два массива: массив хэшей идентификаторов, массив хэшей имён файлов. Далее ксорим каждый хэш имени файла с каждым хэшем идентификатора и получаем массив. Находим в этом массиве индекс минимального элемента. Этот индекс и будет определять ближайшего соседа в массиве всех IP-адрессов пользователей локальной сети. По IP этого соседа мы отправляем ему информацию о том, что у нас содержится тот или иной файл. Все принятые хэши от соседей выводим в файл file-storage.txt.

Протоколы обмена сообщениями:
 * Когда запрашиваемый обладает ссылкой на искомую информацию — [5, IDanswerer, IDdata, IDlinkeddata, original_lengthUINT16, original_name_lengthUINT16, original_name]
 * Ответ в ситуации, когда запрашиваемый обладает искомой информацией — [7, IDanswerer, IDdata, info_lengthUINT16, name_lengthUINT16, name]

P.S. Код вышел беспонтовым, тем не менее всё так себе, но работает.