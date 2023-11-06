package util

func RemoveRepeatElement[T comparable](list []T) []T {
	// 创建一个临时map用来存储数组元素
	temp := make(map[T]struct{})
	index := 0
	// 将元素放入map中
	for _, v := range list {
		temp[v] = struct{}{}
	}
	tempList := make([]T, len(temp))
	for key := range temp {
		tempList[index] = key
		index++
	}
	return tempList
}

func DeleteElement[T comparable](list []T, ele T) []T {
	result := make([]T, 0)
	for _, v := range list {
		if v != ele {
			result = append(result, v)
		}
	}
	return result
}
func ContainsElement[T comparable](list []T, ele T) bool {
	for _, v := range list {
		if v == ele {

			return true
		}
	}
	return false
}
