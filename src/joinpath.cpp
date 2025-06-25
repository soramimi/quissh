#include "joinpath.h"
#include <sstream>
#include <vector>
#include <cstring>

#ifdef WIN32
#pragma warning(disable:4996)
#endif

template <typename T> static inline void trimquot(T const **begin, T const **end)
{
	if (*begin + 1 < *end && (*begin)[0] == '"' && (*end)[-1] == '"') {
		(*begin)++;
		(*end)--;
	}
}

/**
 * @brief 2つのパスを結合する。
 *
 * 左右のパス文字列を結合して、1つのパス文字列にします。
 * 与えられた2つのパス文字列の両端のクォートや不要な区切り文字を取り除いた後、
 * 2つのパスを '/' 区切り文字で結合します。
 *
 * @tparam T 文字列要素の型（char, wchar_t など）。
 * @tparam U 結合されたパスを格納するコンテナの型（std::string, std::wstring など）。
 * @param left 結合する左側のパス文字列。
 * @param right 結合する右側のパス文字列。
 * @param vec 結合されたパスを格納するコンテナへのポインタ。
 */
template <typename T, typename U> void joinpath_(T const *left, T const *right, U *vec)
{
	size_t llen = 0;
	size_t rlen = 0;
	if (left) {
		T const *leftend = left + std::char_traits<T>::length(left);
		trimquot(&left, &leftend);
		while (left < leftend && (leftend[-1] == '/' || leftend[-1] == '\\')) {
			leftend--;
		}
		llen = leftend - left;
	}
	if (right) {
		T const *rightend = right + std::char_traits<T>::length(right);
		trimquot(&right, &rightend);
		while (right < rightend && (right[0] == '/' || right[0] == '\\')) {
			right++;
		}
		rlen = rightend - right;
	}
	vec->resize(llen + 1 + rlen);
	if (llen > 0) {
		std::char_traits<T>::copy(&vec->at(0), left, llen);
	}
	vec->at(llen) = '/';
	if (rlen > 0) {
		std::char_traits<T>::copy(&vec->at(llen + 1), right, rlen);
	}
}

std::string joinpath(char const *left, char const *right)
{
	std::vector<char> vec;
	joinpath_(left, right, &vec);
	return std::string(vec.begin(), vec.end());
}

std::string joinpath(std::string const &left, std::string const &right)
{
	return joinpath(left.c_str(), right.c_str());
}

