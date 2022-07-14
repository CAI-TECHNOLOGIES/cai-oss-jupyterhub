import React from "react";
import { Link } from "react-router-dom";
import PropTypes from "prop-types";

import "./pagination-footer.css";

const PaginationFooter = (props) => {
  apis = props.apis
  let { endpoint, page, limit, numOffset, numElements } = apis;
  return (
    <div className="pagination-footer">
      <p>
        Displaying {numOffset}-{numOffset + numElements}
        <br></br>
        <br></br>
        {page >= 1 ? (
          <button className="btn btn-sm btn-light spaced">
            <Link to={`${endpoint}?page=${page - 1}`}>
              <span className="active-pagination">Previous</span>
            </Link>
          </button>
        ) : (
          <button className="btn btn-sm btn-light spaced">
            <span className="inactive-pagination">Previous</span>
          </button>
        )}
        {numElements >= limit ? (
          <button className="btn btn-sm btn-light spaced">
            <Link to={`${endpoint}?page=${page + 1}`}>
              <span className="active-pagination">Next</span>
            </Link>
          </button>
        ) : (
          <button className="btn btn-sm btn-light spaced">
            <span className="inactive-pagination">Next</span>
          </button>
        )}
      </p>
    </div>
  );
};

export default PaginationFooter;
