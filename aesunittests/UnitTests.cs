using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace AesUnitTests
{
    [TestClass]
    public class UnitTests
    {
        // RED_TAG: These set of tests run the first round only.
        //          Do you think there is merit in confirming
        //          intermidate results through all rounds
        //          given there is a subtle difference in the algorithm
        //          in the last round. 
        //          The counter argument willbe we have an end-to-end test
        //          in our integration testing routine.

        #region 128  bits key cipher tests

        /// <summary>
        /// See http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf, page 36 of the link to review the test input data
        /// </summary>
        [TestMethod]
        public void SubBytes128_ValidInput_Succeeds()
        {
            byte[] input = new byte[]{ 0, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8, 0, 9, 0, 10, 0, 11, 0, 12, 0, 13, 0, 14, 0, 15, 0  };

            hilcoe.securityCourse.AES.SubBytes(ref input);

            byte[] expected = new byte[] { 6, 3, 12, 10, 11,7, 0, 4, 0, 9, 5, 3, 13, 0, 5, 1, 12, 13, 6, 0, 14, 0, 14, 7, 11, 10, 7, 0, 14, 1, 8, 12 };

            Assert.AreEqual(expected, input);
        }

        /// <summary>
        /// See http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf, page 36 of the link to review the test input data
        /// </summary>
        [TestMethod]
        public void ShiftRows128_ValidInput_Succeeds()
        {
            byte[] input = new byte[] { 6, 3, 12, 10, 11, 7, 0, 4, 0, 9, 5, 3, 13, 0, 5, 1, 12, 13, 6, 0, 14, 0, 14, 7, 11, 10, 7, 0, 14, 1, 8, 12 };

            hilcoe.securityCourse.AES.ShiftRows(ref input);

            byte[] expected = new byte[] { 6, 3, 5, 3, 14, 0, 8, 12, 0, 9, 6, 0, 14, 1, 0, 4, 12, 13, 7, 0, 11, 7, 5, 1, 11, 10, 12, 10, 13, 0, 14, 7 };

            Assert.AreEqual(expected, input);
        }

        /// <summary>
        /// See http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf, page 36 of the link to review the test input data
        /// </summary>
        [TestMethod]
        public void MixColumns128_ValidInput_Succeeds()
        {
            byte[] input = new byte[] { 6, 3, 5, 3, 14, 0, 8, 12, 0, 9, 6, 0, 14, 1, 0, 4, 12, 13, 7, 0, 11, 7, 5, 1, 11, 10, 12, 10, 13, 0, 14, 7 };

            hilcoe.securityCourse.AES.MixColumns(ref input);

            byte[] expected = new byte[] { 5, 15, 7, 2, 6, 4, 1, 5, 5, 7, 15, 5, 11, 12, 9, 2, 15, 7, 11, 14, 3, 11, 2, 9, 1, 13, 11, 9, 15, 9, 1, 10 };

            Assert.AreEqual(expected, input);
        }

        /// <summary>
        /// See http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf, page 36 of the link to review the test input data
        /// </summary>
        [TestMethod]
        public void AddRoundKey128_ValidInput_Succeeds()
        {
            //TODO: Requires the keyexpansion algorithm.

            byte[] input = new byte[] { 5, 15, 7, 2, 6, 4, 1, 5, 5, 7, 15, 5, 11, 12, 9, 2, 15, 7, 11, 14, 3, 11, 2, 9, 1, 13, 11, 9, 15, 9, 1, 10 };

            byte[] key = new byte[] { };

            hilcoe.securityCourse.AES.AddRoundKey(ref input, key);

            byte[] expected = new byte[] { 13, 6, 10, 10, 7, 4, 15, 13, 13, 2, 10, 15, 7, 2, 15, 10, 13, 10, 10, 6, 7, 8, 15, 1, 13, 6, 10, 11, 7, 6, 15, 14 };

            Assert.AreEqual(expected, input);
        }

        #endregion
    }
}
